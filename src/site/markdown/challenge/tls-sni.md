# TLS-SNI

With the TLS-SNI challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a SNI request with a self-signed cert.

After authorizing the challenge, `TlsSniChallenge` provides a subject:

```java
TlsSniChallenge challenge = auth.findChallenge(TlsSniChallenge.TYPE);
challenge.authorize(account);

String subject = challenge.getSubject();
```

The `subject` is basically a domain name formed like in this example:

```
30c452b9bd088cdbc2c4094947025d7c.7364ea602ac325a1b55ceaae024fbe29.acme.invalid
```

You need to create a self-signed certificate with the subject set as _Subject Alternative Name_. After that, configure your web server so it will use this certificate on a SNI request to the  `subject`.

The `TlsSniChallenge` class does not generate a self-signed certificate, as it would require _Bouncy Castle_. However, there is a utility method in the _acme4j-utils_ module for this use case:

```java
X509Certificate cert = CertificateUtils.createTlsSniCertificate(String subject);
```

The challenge is completed when the CA was able to send the SNI request and get the correct certificate in return.
