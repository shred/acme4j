# Request a Certificate

Once you completed all the previous steps, it's time to request the signed certificate.

To do so, prepare a PKCS#10 CSR file. A single domain may be set as _Common Name_. Multiple domains must be provided as _Subject Alternative Name_. Other properties (_Organization_, _Organization Unit_ etc.) depend on the CA. Some may require these properties to be set, while others may ignore them when generating the certificate.

CSR files can be generated with command line tools like `openssl`. Unfortunately the standard Java does not offer classes for that, so you'd have to resort to [Bouncy Castle](http://www.bouncycastle.org/java.html) if you want to create a CSR programmatically. In the `acme4j-utils` module, there is also a [`CSRBuilder`](../apidocs/org/shredzone/acme4j/util/CSRBuilder.html) for your convenience:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.addDomain("www.example.org");
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

## Renewal

Renewing your certificate depends on the CA. Some may require you to go through the authorization process again, while others may just provide an updated certificate for download at the `certUri` above.
