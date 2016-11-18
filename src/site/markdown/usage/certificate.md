# Certificates

Once you completed all the previous steps, it's time to request the signed certificate.

## Request a Certificate

To do so, prepare a PKCS#10 CSR file. A single domain may be set as _Common Name_. Multiple domains must be provided as _Subject Alternative Name_. Other properties (_Organization_, _Organization Unit_ etc.) depend on the CA. Some may require these properties to be set, while others may ignore them when generating the certificate.

CSR files can be generated with command line tools like `openssl`. Unfortunately the standard Java does not offer classes for that, so you'd have to resort to [Bouncy Castle](http://www.bouncycastle.org/java.html) if you want to create a CSR programmatically. In the `acme4j-utils` module, there is a [`CSRBuilder`](../apidocs/org/shredzone/acme4j/util/CSRBuilder.html) for your convenience. You can also use [`KeyPairUtils`](../apidocs/org/shredzone/acme4j/util/KeyPairUtils.html) for generating the domain key pair.

Do not just use your account key pair as domain key pair, but always generate a separate pair of keys!

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.setOrganization("The Example Organization")
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

It is a good idea to store the generated CSR somewhere, as you will need it again for renewal:

```java
try (FileWriter fw = new FileWriter("example.csr")) {
    csrb.write(fw);
}
```

Now all you need to do is to pass in a binary representation of the CSR and request the certificate:

```java
Certificate cert = registration.requestCertificate(csr);
```

`cert.getLocation()` returns an URI where the signed certificate can be downloaded from. Optionally (if delivered by the ACME server) `cert.getChainLocation()` returns the URI of the first part of the CA chain.

The `Certificate` object offers methods to download the certificate and the certificate chain.

```java
X509Certificate cert = cert.download();
X509Certificate[] chain = cert.downloadChain();
```

Congratulations! You have just created your first certificate via _acme4j_.

`download()` may throw an `AcmeRetryAfterException`, giving an estimated time in `getRetryAfter()` for when the certificate is ready for download. You should then wait until that moment has been reached, before trying again.

To recreate a `Certificate` object from the location, just bind it:

```java
URI locationUri = ... // location URI from cert.getLocation()
Certificate cert = Certificate.bind(session, locationUri);
```

### Saving Certificates

Most web servers, like _Apache_, _nginx_, but also other servers like _postfix_ or _dovecot_, need a combined certificate file that contains the leaf certificate itself, and the certificate chain up to the root certificate. `acme4j-utils` offers a method that helps to write the necessary file:

```java
try (FileWriter fw = new FileWriter("cert-chain.crt")) {
    CertificateUtils.writeX509CertificateChain(fw, cert, chain);
}
```

Some older servers may need the leaf certificate and the certificate chain in different files. Use this snippet to write both files:

```java
try (FileWriter fw = new FileWriter("cert.pem")) {
    CertificateUtils.writeX509Certificate(cert, fw);
}
try (FileWriter fw = new FileWriter("chain.pem")) {
    CertificateUtils.writeX509CertificateChain(fw, null, chain);
}
```

These utility methods should be sufficient for most use cases. If you need the certificate written in a different format, see the [source code of `CertificateUtils`](https://github.com/shred/acme4j/blob/master/acme4j-utils/src/main/java/org/shredzone/acme4j/util/CertificateUtils.java) to find out how certificates are written using _Bouncy Castle_.

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
// add more domains if necessary...

csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

The generated certificate will be valid for all of the domains.

Note that wildcard certificates are currently not supported by the ACME protocol.

The number of domains per certificate may also be limited. See your CA's documentation for the limits.

## Renewal

Certificates are only valid for a limited time, and need to be renewed before expiry. To find out the expiry date of a `X509Certificate`, invoke its `getNotAfter()` method.

For renewal, just request a new certificate using the original CSR:

```java
PKCS10CertificationRequest csr = CertificateUtils.readCSR(
    new FileInputStream("example.csr"));

Certificate cert = registration.requestCertificate(csr);
X509Certificate cert = cert.download();
```

Instead of loading the original CSR, you can also generate a new one. So renewing a certificate is basically the same as requesting a new certificate.

## Revocation

To revoke a certificate, just invoke the respective method:

```java
cert.revoke();
```

Optionally, you can provide a revocation reason that the ACME server may use when generating OCSP responses and CRLs.

```java
cert.revoke(RevocationReason.KEY_COMPROMISE);
```
