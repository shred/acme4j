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
package org.shredzone.acme4j.example;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import javax.swing.JOptionPane;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple client test tool.
 * <p>
 * Pass the names of the domains as parameters.
 */
public class ClientTest {
    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // File name of the CSR
    private static final File DOMAIN_CSR_FILE = new File("domain.csr");

    // File name of the signed certificate
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");

    //Challenge type to be used
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    private static final Logger LOG = LoggerFactory.getLogger(ClientTest.class);

    private enum ChallengeType {HTTP, DNS}

    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *         Domains to get a common certificate for
     * @param eabKid
     *         Value of --eab-kid
     * @param eabHmacKey
     *         Value of --eab-hmac-key
     * @param emailAddress
     *         Email address of account that owns the key information
     */
    public void fetchCertificate(Collection<String> domains, String eabKid, String eabHmacKey, String emailAddress) throws IOException, AcmeException {
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadOrCreateUserKeyPair();

        // Create a session for Let's Encrypt.
        // Use "acme://letsencrypt.org" for production server
        Session session = new Session("acme://ssl.com/staging");
        //Session session = new Session("acme://letsencrypt.org/staging");

        // Get the Account.
        // If there is no account yet, create a new one.
        Account acct = findOrRegisterAccount(session, userKeyPair, eabKid, eabHmacKey, emailAddress);

        // Load or create a key pair for the domains. This should not be the userKeyPair!
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();

        // Order the certificate
        Order order = acct.newOrder().domains(domains).create();

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // Order the certificate
        order.execute(domainKeyPair);

        // Wait for the order to complete
        try {
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the order fail?
                if (order.getStatus() == Status.INVALID) {
                    LOG.error("Order has failed, reason: {}", order.getError()
                            .map(Problem::toString)
                            .orElse("unknown")
                    );
                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        Certificate certificate = order.getCertificate();

        LOG.info("Success! The certificate for domains {} has been generated!", domains);
        LOG.info("Certificate URL: {}", certificate.getLocation());

        // Write a combined file containing the certificate and chain.
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
        }

        // That's all! Configure your web server to use the DOMAIN_KEY_FILE and
        // DOMAIN_CHAIN_FILE for the requested domains.
    }

    /**
     * Loads a user key pair from {@link #USER_KEY_FILE}. If the file does not exist, a
     * new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }

        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    /**
     * Loads a domain key pair from {@link #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL of your new account with {@link Account#getLocation()} and store it somewhere.
     * If you need to get access to your account later, reconnect to it via {@link
     * Session#login(URL, KeyPair)} by using the stored location.
     *
     * @param session
     *         {@link Session} to bind with
     * @param eabKid
     *         Value of --eab-kid
     * @param eabHmacKey
     *         Value of --eab-hmac-key
     * @param emailAddress
     *         Email address of account that owns the key information
     * @return {@link Account}
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey, String eabKid, String eabHmacKey, String emailAddress) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        Optional<URI> tos = session.getMetadata().getTermsOfService();
        if (tos.isPresent()) {
            acceptAgreement(tos.get());
        }

        AccountBuilder accountBuilder = new AccountBuilder();
        if (eabKid != null && eabHmacKey != null && emailAddress != null) {
            accountBuilder = accountBuilder.withKeyIdentifier(eabKid, eabHmacKey)
                    .addEmail(emailAddress);
        }
        Account account = accountBuilder
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        LOG.info("Registered a new user, URL: {}", account.getLocation());

        return account;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *         {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException {
        LOG.info("Authorization for domain {}", auth.getIdentifier().getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = null;
        switch (CHALLENGE_TYPE) {
            case HTTP:
                challenge = httpChallenge(auth);
                break;

            case DNS:
                challenge = dnsChallenge(auth);
                break;
        }

        if (challenge == null) {
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    LOG.error("Challenge has failed, reason: {}", challenge.getError()
                            .map(Problem::toString)
                            .orElse("unknown"));
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getIdentifier().getDomain() + ", ... Giving up.");
        }

        LOG.info("Challenge has been completed. Remember to remove the validation resource.");
        completeChallenge("Challenge has been completed.\nYou can remove the resource again now.");
    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to be
     * reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or maybe
     * use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth
     *         {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new AcmeException("Found no " + Http01Challenge.TYPE
                        + " challenge, don't know what to do..."));

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a file in your web server's base directory.");
        LOG.info("It must be reachable at: http://{}/.well-known/acme-challenge/{}",
                auth.getIdentifier().getDomain(), challenge.getToken());
        LOG.info("File name: {}", challenge.getToken());
        LOG.info("Content: {}", challenge.getAuthorization());
        LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!");
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a file in your web server's base directory.\n\n");
        message.append("http://")
                .append(auth.getIdentifier().getDomain())
                .append("/.well-known/acme-challenge/")
                .append(challenge.getToken())
                .append("\n\n");
        message.append("Content:\n\n");
        message.append(challenge.getAuthorization());
        acceptChallenge(message.toString());

        return challenge;
    }

    /**
     * Prepares a DNS challenge.
     * <p>
     * The verification of this challenge expects a TXT record with a certain content.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather configure your DNS automatically.
     *
     * @param auth
     *         {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge dnsChallenge(Authorization auth) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                .map(Dns01Challenge.class::cast)
                .orElseThrow(() -> new AcmeException("Found no " + Dns01Challenge.TYPE
                        + " challenge, don't know what to do..."));

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a TXT record:");
        LOG.info("{} IN TXT {}",
                Dns01Challenge.toRRName(auth.getIdentifier()), challenge.getDigest());
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a TXT record:\n\n");
        message.append(Dns01Challenge.toRRName(auth.getIdentifier()))
                .append(" IN TXT ")
                .append(challenge.getDigest());
        acceptChallenge(message.toString());

        return challenge;
    }

    /**
     * Presents the instructions for preparing the challenge validation, and waits for
     * dismissal. If the user cancelled the dialog, an exception is thrown.
     *
     * @param message
     *         Instructions to be shown in the dialog
     */
    public void acceptChallenge(String message) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                message,
                "Prepare Challenge",
                JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            throw new AcmeException("User cancelled the challenge");
        }
    }

    /**
     * Presents the instructions for removing the challenge validation, and waits for
     * dismissal.
     *
     * @param message
     *         Instructions to be shown in the dialog
     */
    public void completeChallenge(String message) {
        JOptionPane.showMessageDialog(null,
                message,
                "Complete Challenge",
                JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Presents the user a link to the Terms of Service, and asks for confirmation. If the
     * user denies confirmation, an exception is thrown.
     *
     * @param agreement
     *         {@link URI} of the Terms of Service
     */
    public void acceptAgreement(URI agreement) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                "Do you accept the Terms of Service?\n\n" + agreement,
                "Accept ToS",
                JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            throw new AcmeException("User did not accept Terms of Service");
        }
    }

    /**
     * Invokes this example.
     *
     * @param args
     *         Domains to get a certificate for
     */
    public static void main(String... args) {
        if (args.length == 0) {
            System.err.println("Usage: ClientTest <domain,domain,...> <eab-kid>(optional) <eab-hmac-key>(optional) <account-email>(optional)");
            System.exit(1);
        }

        LOG.info("Starting up...");

        Security.addProvider(new BouncyCastleProvider());

        Collection<String> domains = Arrays.asList(args[0].split(","));
        String eabKid = args.length > 1 ? args[1] : null;
        String eabHmacKey = args.length > 2 ? args[2] : null;
        String emailAddress = args.length > 3 ? args[3] : null;
        try {
            ClientTest ct = new ClientTest();
            ct.fetchCertificate(domains, eabKid, eabHmacKey, emailAddress);
        } catch (Exception ex) {
            LOG.error("Failed to get a certificate for domains " + domains, ex);
        }
    }

}
