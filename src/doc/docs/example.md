# Example

For a quick start, there is a simple example provided in the `acme4j-example` module. The example class is named `org.shredzone.acme4j.example.ClientTest`. It will demonstrate all the steps that are necessary for generating key pairs, authorizing domains, and ordering a certificate.

This chapter contains a copy of the class file, along with explanations about what is happening.

## Caveats

- The `ClientTest` is meant to be a simple example and proof of concept. It is not meant for production use as it is.

- The exception handling is very simple. If an exception occurs during the process, the example will fail altogether. A real client should handle exceptions like `AcmeUserActionRequiredException`, `AcmeRateLimitedException`, and `AcmeRetryAfterException` properly, by showing the required user action, or delaying the registration process until the rate limitation has been lifted or the retry time has been reached.

- At some places the example polls the server state by `while` loops and `Thread.sleep()`. This is sufficient for simple cases, but a more complex client should use timers instead. The client should also make use of the fact that authorizations can be executed in parallel, shortening the certification time for multiple domains.

- I recommend to read at least the chapters about [usage](usage/index.md) and [challenges](challenge/index.md), to learn more about how _acme4j_ and the ACME protocol works.

- To make the example easier to understand, I will use the specific datatypes instead of the `var` keyword.

## Running the Example

You can run the `ClientTest` class in your IDE, giving the domain names to be registered as parameters. When changing into the `acme4j-example` directory, the test client can also be invoked via maven in a command line:

```sh
mvn exec:java -Dexec.args="example.com example.org"
```

It is safe to run the example in the default configuration. The domains will be registered with the _Let's Encrypt staging server_ via HTTP challenges. The generated certificates are test certificates that are not suited for production use, as they will be rejected by all standard browsers.

## Invocation

The `main()` method performs a simple parameter check, and then invokes the `ClientTest.fetchCertificate()` method, giving a collection of domain names to get a certificate for.

```java
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
```

!!! note
    The example requires the `BouncyCastleProvider` to be added as security provider.

## The Main Workflow

The `fetchCertificate()` method contains the main workflow. It expects a collection of domain names.

```java
public void fetchCertificate(Collection<String> domains)
        throws IOException, AcmeException {
    // Load the user key file. If there is no key file, create a new one.
    KeyPair userKeyPair = loadOrCreateUserKeyPair();

    // Create a session for Let's Encrypt.
    // Use "acme://letsencrypt.org" for production server
    Session session = new Session("acme://letsencrypt.org/staging");

    // Get the Account.
    // If there is no account yet, create a new one.
    Account acct = findOrRegisterAccount(session, userKeyPair);

    // Load or create a key pair for the domains.
    // This should not be the userKeyPair!
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

    // That's all! Configure your web server to use the
    // DOMAIN_KEY_FILE and DOMAIN_CHAIN_FILE for the
    // requested domains.
}
```

When this method returned successfully, you will find the domain key pair in a file that is named `domain.key`, and the certificate (including the full certificate path) in a file named `domain-chain.crt`.

If no account was registered with the CA yet, there will also be a new file called `user.key`, which is your account key pair.

The `domain.csr` file contains the CSR that was used for the cerficiate order. It is just written for example purposes, and will not be needed later again. When the certificate is going to be renewed, a new CSR will be generated.

## Creating Key Pairs

There are two sets of key pairs. One is required for creating and accessing your account, the other is required for encrypting the traffic on your domain(s). Even though it is technically possible to use a common key pair for everything, you are strongly encouraged to use separate key pairs for your account and for each of your certificates.

A first helper method looks for a file that is called `user.key`. It will contain the key pair that is required for accessing your account. If there is no such key pair, a new one is generated.

!!! important
    Backup this key pair in a safe place, as you will be locked out from your account if you should ever lose it! There is no way to recover a lost key pair, or regain access to your account when the key is lost.

```java
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
```

A second helper generates a new `domain.key` file unless it is already present.

```java
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
```

Both the user and domain key pairs are of the same type and strength in this example. This is not required though. You can mix RSA and EC keys of different strengths.

## Registering an Account

If you does not have an account set up already, you need to create one first. The following method will show a link to the terms of service and ask you to accept it. After that, the `AccountBuilder` will create an account using the given account `KeyPair`.

If your `KeyPair` has already been registered with the CA, no new account will be created, but your existing account will be used.

```java
private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
    // Ask the user to accept the TOS, if server provides us with a link.
    Optional<URI> tos = session.getMetadata().getTermsOfService();
    if (tos.isPresent()) {
        acceptAgreement(tos.get());
    }

    Account account = new AccountBuilder()
            .agreeToTermsOfService()
            .useKeyPair(accountKey)
            .create(session);
    LOG.info("Registered a new user, URL: {}", account.getLocation());

    return account;
}
```

!!! note
    The invocation of `agreeToTermsOfService()` is mandatory for creating a new account. Do not just invoke this method, but make sure that the user has actually read and accepted the terms of service.

## Authorizing a Domain

In order to get a certificate, you need to prove ownership of the domains. In this example client, this can be done either by providing a certain file via HTTP, or by setting a certain `TXT` record in your DNS. You can choose the desired challenge type by setting the `CHALLENGE_TYPE` constant. By default, the HTTP challenge is used.

```java
private void authorize(Authorization auth)
        throws AcmeException {
    LOG.info("Authorization for domain {}", auth.getIdentifier().getDomain());

    // The authorization is already valid.
    // No need to process a challenge.
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

    // If the challenge is already verified,
    // there's no need to execute it again.
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
                        .orElse("unknown")
                );
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

    // All reattempts are used up and there is
    // still no valid authorization?
    if (challenge.getStatus() != Status.VALID) {
        throw new AcmeException("Failed to pass the challenge for domain "
                + auth.getIdentifier().getDomain() + ", ... Giving up.");
    }

    LOG.info("Challenge has been completed. Remember to remove the validation resource.");
    completeChallenge("Challenge has been completed.\nYou can remove the resource again now.");
}
```

## HTTP Challenge

For the HTTP challenge, your server must provide a certain file in the `/.well-known/acme-challenge/` path. This file must be accessible via GET request to your domain. The request is always performed against port 80, but the CA will follow HTTP redirects. If there is a redirection to HTTPS, an invalid (e.g. self-signed, mismatched, or expired) certificate will be accepted by the CA so that the challenge can be completed.

In this example, a modal dialog will describe the file name and file content that needs to be used for the challenge. You have to manually set up your web server, so it will provide the file on the specified path. After that, confirm the dialog to trigger the challenge.

When the authorization process is completed, the file is not used any more and can be safely deleted.

```java
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
```

This is the default challenge of the example, and probably also the most commonly used challenge. However, the CA may also offer other challenges, like the DNS challenge.

## DNS Challenge

For this challenge, a `TXT` record with a given token needs to be created for the domain to be validated.

Again, a modal dialog will describe the name and content of the `TXT` record. You have to manually configure your DNS server accordingly. After that, confirm the dialog to trigger the challenge.

When the authorization has been completed, the `TXT` record can be safely removed again.

```java
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
```

!!! note
    Make sure that the `TXT` record is actually available before confirming the dialog. The CA may verify the challenge immediately after it was triggered. The challenge will then fail if your DNS server was not ready yet. Depending on your hosting provider, a DNS update may take several minutes until completed.

!!! note
    For security reasons, the DNS challenge is mandatory for creating wildcard certificates.

## User Interaction

In order to keep the example simple, Swing `JOptionPane` dialogs are used for user communication. If the user rejects a dialog, an exception is thrown and the example client is aborted.

```java
public void acceptChallenge(String message) throws AcmeException {
    int option = JOptionPane.showConfirmDialog(null,
            message,
            "Prepare Challenge",
            JOptionPane.OK_CANCEL_OPTION);
    if (option == JOptionPane.CANCEL_OPTION) {
        throw new AcmeException("User cancelled the challenge");
    }
}

public void completeChallenge(String message) {
    JOptionPane.showMessageDialog(null,
            message,
            "Complete Challenge",
            JOptionPane.INFORMATION_MESSAGE);
}

public void acceptAgreement(URI agreement) throws AcmeException {
    int option = JOptionPane.showConfirmDialog(null,
            "Do you accept the Terms of Service?\n\n" + agreement,
            "Accept ToS",
            JOptionPane.YES_NO_OPTION);
    if (option == JOptionPane.NO_OPTION) {
        throw new AcmeException("User did not accept Terms of Service");
    }
}
```

## Constants

These are the default values of the constants used in this example. Feel free to change them as necessary.

```java
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
```
