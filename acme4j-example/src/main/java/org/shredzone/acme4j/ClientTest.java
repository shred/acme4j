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
 *
 * @author Richard "Shred" Körber
 */
public class ClientTest {
    private static final File USER_KEY_FILE = new File("user.key");
    private static final File DOMAIN_KEY_FILE = new File("domain.key");
    private static final File DOMAIN_CERT_FILE = new File("domain.crt");
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

        // Create an AcmeClient for Let's Encrypt
        // Use "acme://letsencrypt.org" for production server
        AcmeClient client = AcmeClientFactory.connect("acme://letsencrypt.org/staging");

        // Register a new user
        Registration reg = new Registration(userKeyPair);
        try {
            client.newRegistration(reg);
            LOG.info("Registered a new user, URI: " + reg.getLocation());
        } catch (AcmeConflictException ex) {
            LOG.info("Account does already exist, URI: " + reg.getLocation());
        }

        LOG.info("Terms of Service: " + reg.getAgreement());

        if (createdNewKeyPair) {
            boolean accepted = acceptAgreement(client, reg);
            if (!accepted) {
                return;
            }
        }


        for (String domain : domains) {
            // Create a new authorization
            Authorization auth = new Authorization();
            auth.setDomain(domain);
            try {
                client.newAuthorization(reg, auth);
            } catch (AcmeUnauthorizedException ex) {
                // Maybe there are new T&C to accept?
                boolean accepted = acceptAgreement(client, reg);
                if (!accepted) {
                    return;
                }
                // Then try again...
                client.newAuthorization(reg, auth);
            }
            LOG.info("New authorization for domain " + domain);

            // Uncomment a challenge...
            Challenge challenge = httpChallenge(auth, reg, domain);
//            Challenge challenge = dnsChallenge(auth, reg, domain);
//            Challenge challenge = tlsSniChallenge(auth, reg, domain);

            if (challenge == null) {
                return;
            }

            // Trigger the challenge
            client.triggerChallenge(reg, challenge);

            // Poll for the challenge to complete
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                if (challenge.getStatus() == Status.INVALID) {
                    LOG.error("Challenge failed... Giving up.");
                    return;
                }
                try {
                    Thread.sleep(3000L);
                } catch (InterruptedException ex) {
                    LOG.warn("interrupted", ex);
                }
                client.updateChallenge(challenge);
            }
            if (attempts == 0) {
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
        URI certificateUri = client.requestCertificate(reg, csrb.getEncoded());
        LOG.info("Success! The certificate for domains " + domains + " has been generated!");
        LOG.info("Certificate URI: " + certificateUri);

        // Download the certificate
        X509Certificate cert = client.downloadCertificate(certificateUri);
        try (FileWriter fw = new FileWriter(DOMAIN_CERT_FILE)) {
            CertificateUtils.writeX509Certificate(cert, fw);
        }

        // Revoke the certificate (uncomment if needed...)
        // client.revokeCertificate(reg, cert);
    }

    /**
     * Prepares HTTP challenge.
     */
    public Challenge httpChallenge(Authorization auth, Registration reg, String domain) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Authorize the challenge
        challenge.authorize(reg);

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
    public Challenge dnsChallenge(Authorization auth, Registration reg, String domain) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Authorize the challenge
        challenge.authorize(reg);

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
    public Challenge tlsSniChallenge(Authorization auth, Registration reg, String domain) throws AcmeException {
        // Find a single tls-sni-01 challenge
        org.shredzone.acme4j.challenge.TlsSni01Challenge challenge = auth.findChallenge(org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE);
        if (challenge == null) {
            LOG.error("Found no " + org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE + " challenge, don't know what to do...");
            return null;
        }

        // Authorize the challenge
        challenge.authorize(reg);

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
     * @param client
     *            {@link AcmeClient} to send confirmation to
     * @param reg
     *            {@link Registration} User's registration, containing the Agreement URI
     * @return {@code true}: User confirmed, {@code false} user rejected
     */
    public boolean acceptAgreement(AcmeClient client, Registration reg)
                throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                        "Do you accept the Terms of Service?\n\n" + reg.getAgreement(),
                        "Accept T&C",
                        JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            LOG.error("User did not accept Terms of Service");
            return false;
        }

        client.modifyRegistration(reg);
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
