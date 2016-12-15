/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import javax.swing.JOptionPane;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple client test tool.
 * <p>
 * Pass the names of the domains as parameters.
 */
public class ClientTest {
    private static final File USER_KEY_FILE = new File("user.key");
    private static final File DOMAIN_KEY_FILE = new File("domain.key");
    private static final File DOMAIN_CERT_FILE = new File("domain.crt");
    private static final File CERT_CHAIN_FILE = new File("chain.crt");
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");
    private static final File DOMAIN_CSR_FILE = new File("domain.csr");

    private static final int KEY_SIZE = 2048;

    private static final Logger LOG = LoggerFactory.getLogger(ClientTest.class);

    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *            Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
        // Load or create a key pair for the user's account
        boolean createdNewKeyPair = false;

        KeyPair userKeyPair;
        if (USER_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                userKeyPair = KeyPairUtils.readKeyPair(fr);
            }
        } else {
            userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            createdNewKeyPair = true;
        }

        // Create a session for Let's Encrypt
        // Use "acme://letsencrypt.org" for production server
        Session session = new Session("acme://letsencrypt.org/staging", userKeyPair);

        // Register a new user
        Registration reg = null;
        try {
            reg = new RegistrationBuilder().create(session);
            LOG.info("Registered a new user, URI: " + reg.getLocation());
        } catch (AcmeConflictException ex) {
            LOG.trace("acme4j exception caught", ex);
            reg = Registration.bind(session, ex.getLocation());
            LOG.info("Account does already exist, URI: " + reg.getLocation());
        }

        URI agreement = reg.getAgreement();
        LOG.info("Terms of Service: " + agreement);

        if (createdNewKeyPair) {
            boolean accepted = acceptAgreement(reg, agreement);
            if (!accepted) {
                return;
            }
        }

        for (String domain : domains) {
            // Create a new authorization
            Authorization auth = null;
            try {
                auth = reg.authorizeDomain(domain);
            } catch (AcmeUnauthorizedException ex) {
                // Maybe there are new T&C to accept?
                LOG.trace("acme4j exception caught", ex);
                boolean accepted = acceptAgreement(reg, agreement);
                if (!accepted) {
                    return;
                }
                // Then try again...
                auth = reg.authorizeDomain(domain);
            }
            LOG.info("New authorization for domain " + domain);

            // Uncomment a challenge...
            Challenge challenge = httpChallenge(auth, domain);
//            Challenge challenge = dnsChallenge(auth, domain);
//            Challenge challenge = tlsSniChallenge(auth, domain);

            if (challenge == null) {
                return;
            }

            // Trigger the challenge
            challenge.trigger();

            // Poll for the challenge to complete
            try {
                int attempts = 10;
                while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                    if (challenge.getStatus() == Status.INVALID) {
                        LOG.error("Challenge failed... Giving up.");
                        return;
                    }
                    Thread.sleep(3000L);
                    challenge.update();
                }
            } catch (InterruptedException ex) {
                LOG.error("interrupted", ex);
                Thread.currentThread().interrupt();
            }

            if (challenge.getStatus() != Status.VALID) {
                LOG.error("Failed to pass the challenge... Giving up.");
                return;
            }
        }

        // Load or create a key pair for the domain
        KeyPair domainKeyPair;
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                domainKeyPair = KeyPairUtils.readKeyPair(fr);
            }
        } else {
            domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
        }

        // Generate a CSR for the domain
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        csrb.sign(domainKeyPair);

        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out);
        }

        // Request a signed certificate
        Certificate certificate = reg.requestCertificate(csrb.getEncoded());
        LOG.info("Success! The certificate for domains " + domains + " has been generated!");
        LOG.info("Certificate URI: " + certificate.getLocation());

        // Download the certificate
        X509Certificate cert = certificate.download();
        X509Certificate[] chain = certificate.downloadChain();

        // Write certificate only (e.g. for Apache's SSLCertificateFile)
        try (FileWriter fw = new FileWriter(DOMAIN_CERT_FILE)) {
            CertificateUtils.writeX509Certificate(cert, fw);
        }

        // Write chain only (e.g. for Apache's SSLCertificateChainFile)
        try (FileWriter fw = new FileWriter(CERT_CHAIN_FILE)) {
            CertificateUtils.writeX509CertificateChain(fw, null, chain);
        }

        // Write combined certificate and chain (e.g. for nginx)
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            CertificateUtils.writeX509CertificateChain(fw, cert, chain);
        }

        // Revoke the certificate (uncomment if needed...)
        // certificate.revoke();

        // Deactivate the registration (uncomment if needed...)
        // reg.deactivate();
    }

    /**
     * Prepares HTTP challenge.
     */
    public Challenge httpChallenge(Authorization auth, String domain) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a file in your web server's base directory.");
        LOG.info("It must be reachable at: http://" + domain + "/.well-known/acme-challenge/" + challenge.getToken());
        LOG.info("File name: " + challenge.getToken());
        LOG.info("Content: " + challenge.getAuthorization());
        LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!");
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a file in your web server's base directory.\n\n");
        message.append("http://").append(domain).append("/.well-known/acme-challenge/").append(challenge.getToken()).append("\n\n");
        message.append("Content:\n\n");
        message.append(challenge.getAuthorization());
        int option = JOptionPane.showConfirmDialog(null,
                        message.toString(),
                        "Prepare Challenge",
                        JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            LOG.error("User cancelled challenge");
            return null;
        }

        return challenge;
    }

    /**
     * Prepares DNS challenge.
     */
    public Challenge dnsChallenge(Authorization auth, String domain) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a TXT record:");
        LOG.info("_acme-challenge." + domain + ". IN TXT " + challenge.getDigest());
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a TXT record:\n\n");
        message.append("_acme-challenge." + domain + ". IN TXT " + challenge.getDigest());
        int option = JOptionPane.showConfirmDialog(null,
                        message.toString(),
                        "Prepare Challenge",
                        JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            LOG.error("User cancelled challenge");
            return null;
        }

        return challenge;
    }

    /**
     * Prepares TLS-SNI challenge.
     */
    @SuppressWarnings("deprecation") // until tls-sni-02 is supported
    public Challenge tlsSniChallenge(Authorization auth, String domain) throws AcmeException {
        // Find a single tls-sni-01 challenge
        org.shredzone.acme4j.challenge.TlsSni01Challenge challenge = auth.findChallenge(org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Get the Subject
        String subject = challenge.getSubject();

        // Create a keypair
        KeyPair domainKeyPair;
        try (FileWriter fw = new FileWriter("tlssni.key")) {
            domainKeyPair = KeyPairUtils.createKeyPair(2048);
            KeyPairUtils.writeKeyPair(domainKeyPair, fw);
        } catch (IOException ex) {
            LOG.error("Could not create keypair", ex);
            return null;
        }

        // Create a certificate
        try (FileWriter fw = new FileWriter("tlssni.crt")) {
            X509Certificate cert = CertificateUtils.createTlsSniCertificate(domainKeyPair, subject);
            CertificateUtils.writeX509Certificate(cert, fw);
        } catch (IOException ex) {
            LOG.error("Could not create certificate", ex);
            return null;
        }

        // Output the challenge, wait for acknowledge...
        LOG.info("Please configure your web server.");
        LOG.info("It must return the certificate 'tlssni.crt' on a SNI request to:");
        LOG.info(subject);
        LOG.info("The matching keypair is available at 'tlssni.key'.");
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please use 'tlssni.key' and 'tlssni.crt' cert for SNI requests to:\n\n");
        message.append("https://").append(subject).append("\n\n");
        int option = JOptionPane.showConfirmDialog(null,
                        message.toString(),
                        "Prepare Challenge",
                        JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            LOG.error("User cancelled challenge");
            return null;
        }

        return challenge;
    }

    /**
     * Presents the user a link to the Terms of Service, and asks for confirmation.
     *
     * @param reg
     *            {@link Registration} User's registration, containing the Agreement URI
     * @return {@code true}: User confirmed, {@code false} user rejected
     */
    public boolean acceptAgreement(Registration reg, URI agreement)
                throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                        "Do you accept the Terms of Service?\n\n" + agreement,
                        "Accept T&C",
                        JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            LOG.error("User did not accept Terms of Service");
            return false;
        }

        reg.modify().setAgreement(agreement).commit();
        LOG.info("Updated user's ToS");

        return true;
    }

    public static void main(String... args) {
        if (args.length == 0) {
            System.err.println("Usage: ClientTest <domain>...");
            System.exit(1);
        }

        LOG.info("Starting up...");

        Security.addProvider(new BouncyCastleProvider());

        Collection<String> domains = Arrays.asList(args);
        try {
            ClientTest ct = new ClientTest();
            ct.fetchCertificate(domains);
        } catch (Exception ex) {
            LOG.error("Failed to get a certificate for domains " + domains, ex);
        }
    }

}
