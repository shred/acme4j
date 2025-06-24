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
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.function.Supplier;

import javax.swing.JOptionPane;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
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
 * First check the configuration constants at the top of the class. Then run the class,
 * and pass in the names of the domains as parameters.
 * <p>
 * The tool won't run as-is. You MUST change the {@link #CA_URI} constant and set the
 * connection URI of your target CA there.
 * <p>
 * If your CA requires External Account Binding (EAB), you MUST also fill the
 * {@link #EAB_KID} and {@link #EAB_HMAC} constants with the values provided by your CA.
 * <p>
 * If your CA requires an email field to be set in your account, you also need to set
 * {@link #ACCOUNT_EMAIL}.
 * <p>
 * All other fields are optional and should work with the default values, unless your CA
 * has special requirements (e.g. to the key type).
 *
 * @see <a href="https://shredzone.org/maven/acme4j/example.html">This example, fully
 * explained in the documentation.</a>
 */
public class ClientTest {
    // Set the Connection URI of your CA here. For testing purposes, use a staging
    // server if possible. Example: "acme://letsencrypt.org/staging" for the Let's
    // Encrypt staging server.
    private static final String CA_URI = "acme://example.com/staging";

    // E-Mail address to be associated with the account. Optional, null if not used.
    private static final String ACCOUNT_EMAIL = null;

    // If the CA requires External Account Binding (EAB), set the provided KID and HMAC here.
    private static final String EAB_KID = null;
    private static final String EAB_HMAC = null;

    // A supplier for a new account KeyPair. The default creates a new EC key pair.
    private static final Supplier<KeyPair> ACCOUNT_KEY_SUPPLIER = KeyPairUtils::createKeyPair;

    // A supplier for a new domain KeyPair. The default creates a RSA key pair.
    private static final Supplier<KeyPair> DOMAIN_KEY_SUPPLIER = () -> KeyPairUtils.createKeyPair(4096);

    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // File name of the signed certificate
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");

    //Challenge type to be used
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

    // Maximum time to wait until VALID/INVALID is expected
    private static final Duration TIMEOUT = Duration.ofSeconds(60L);

    private static final Logger LOG = LoggerFactory.getLogger(ClientTest.class);

    private enum ChallengeType {HTTP, DNS}

    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *         Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException, InterruptedException {
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadOrCreateUserKeyPair();

        // Create a session.
        ISession ISession = new Session(CA_URI);

        // Get the Account.
        // If there is no account yet, create a new one.
        Account acct = findOrRegisterAccount(ISession, userKeyPair);

        // Load or create a key pair for the domains. This should not be the userKeyPair!
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();

        // Order the certificate
        Order order = acct.newOrder().domains(domains).create();

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // Wait for the order to become READY
        order.waitUntilReady(TIMEOUT);

        // Order the certificate
        order.execute(domainKeyPair);

        // Wait for the order to complete
        Status status = order.waitForCompletion(TIMEOUT);
        if (status != Status.VALID) {
            LOG.error("Order has failed, reason: {}", order.getError()
                    .map(Problem::toString)
                    .orElse("unknown"));
            throw new AcmeException("Order failed... Giving up.");
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
            KeyPair userKeyPair = ACCOUNT_KEY_SUPPLIER.get();
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
            KeyPair domainKeyPair = DOMAIN_KEY_SUPPLIER.get();
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
     * @param ISession
     *         {@link Session} to bind with
     * @return {@link Account}
     */
    private Account findOrRegisterAccount(ISession ISession, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        Optional<URI> tos = ISession.getMetadata().getTermsOfService();
        if (tos.isPresent()) {
            acceptAgreement(tos.get());
        }

        AccountBuilder accountBuilder = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey);

        // Set your email (if available)
        if (ACCOUNT_EMAIL != null) {
            accountBuilder.addEmail(ACCOUNT_EMAIL);
        }

        // Use the KID and HMAC if the CA uses External Account Binding
        if (EAB_KID != null && EAB_HMAC != null) {
            accountBuilder.withKeyIdentifier(EAB_KID, EAB_HMAC);
        }

        Account account = accountBuilder.create(ISession);
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
    private void authorize(Authorization auth) throws AcmeException, InterruptedException {
        LOG.info("Authorization for domain {}", auth.getIdentifier().getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = switch (CHALLENGE_TYPE) {
            case HTTP -> httpChallenge(auth);
            case DNS -> dnsChallenge(auth);
        };

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
        Status status = challenge.waitForCompletion(TIMEOUT);
        if (status != Status.VALID) {
            LOG.error("Challenge has failed, reason: {}", challenge.getError()
                    .map(Problem::toString)
                    .orElse("unknown"));
            throw new AcmeException("Challenge failed... Giving up.");
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
                challenge.getRRName(auth.getIdentifier()), challenge.getDigest());
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a TXT record:\n\n");
        message.append(challenge.getRRName(auth.getIdentifier()))
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
