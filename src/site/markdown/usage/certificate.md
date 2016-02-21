# Certificates

Once you completed all the previous steps, it's time to request the signed certificate.

## Request a Certificate

To do so, prepare a PKCS#10 CSR file. A single domain may be set as _Common Name_. Multiple domains must be provided as _Subject Alternative Name_. Other properties (_Organization_, _Organization Unit_ etc.) depend on the CA. Some may require these properties to be set, while others may ignore them when generating the certificate.

CSR files can be generated with command line tools like `openssl`. Unfortunately the standard Java does not offer classes for that, so you'd have to resort to [Bouncy Castle](http://www.bouncycastle.org/java.html) if you want to create a CSR programmatically. In the `acme4j-utils` module, there is also a [`CSRBuilder`](../apidocs/org/shredzone/acme4j/util/CSRBuilder.html) for your convenience. You can also use [`KeyPairUtils`](../apidocs/org/shredzone/acme4j/util/KeyPairUtils.html) for generating the domain key pair.

Do not just use your account key pair as domain key pair, but generate a separate pair of keys!

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.setOrganization("The Example Organization")
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

Now all you need to do is to pass in a binary representation of the CSR and request the certificate:

```java
byte[] csr = ... // your CSR

URI certUri = client.requestCertificate(account, csr);
```

`certUri` contains an URI where the signed certificate can be downloaded from. You can either download it from there yourself (e.g. with `curl`), or just use the `AcmeClient`:

```java
X509Certificate cert = client.downloadCertificate(certUri);
```

Congratulations! You have just created your first certificate via _acme4j_.

### Multiple Domains

The example above generates a certificate per domain. However, you would usually prefer to use a single certificate for multiple domains (for example, the domain itself and the `www.` subdomain).

You first need to [authorize](./authorization.html) each (sub)domain separately.

After all the domains are authorized, generate a single CSR with all the domains provided as _Subject Alternative Name_ (SAN). If you use the `CSRBuilder`, just add all of the domains to the builder:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.addDomain("www.example.org");
csrb.addDomain("m.example.org");
// add more domains if required...

csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

The generated certificate will be valid for all of the domains.

Note that wildcard certificates are currently not supported by the ACME protocol.

The number of domains per certificate may also be limited (_Let's Encrypt_ currently has a limit of 100 SANs per certificate).

## Renewal

Renewing your certificate depends on the CA. Some may require you to go through the authorization process again, while others may just provide an updated certificate for download at the `certUri` above.

## Revocation

To revoke a certificate, just pass the it to the respective method:

```java
X509Certificate cert = ... // certificate to be revoked
client.revokeCertificate(registration, cert);
```

As an exception, ACME servers also accept the domain's key pair for revoking a certificate. _acme4j_ does not directly support this way of revocation. However, you can do so with this tiny hack:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption
X509Certificate cert = ... // certificate to be revoked
client.revokeCertificate(new Registration(domainKeyPair), cert);
```

If you have the choice, you should always prefer to use your account key. In a future version of _acme4j_, this hack might stop working.
