# TLS-SNI

With the TLS-SNI challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a SNI request with a specific self-signed cert.

After authorizing the challenge, `TlsSniChallenge` provides a subject:

```java
TlsSniChallenge challenge = auth.findChallenge(TlsSniChallenge.TYPE);
challenge.authorize(registration);

String subject = challenge.getSubject();
```

The `subject` is basically a domain name formed like in this example:

```
30c452b9bd088cdbc2c4094947025d7c.7364ea602ac325a1b55ceaae024fbe29.acme.invalid
```

You need to create a self-signed certificate with the subject set as _Subject Alternative Name_. After that, configure your web server so it will use this certificate on a SNI request to the `subject`.

The `TlsSniChallenge` class does not generate a self-signed certificate, as it would require _Bouncy Castle_. However, there is a utility method in the _acme4j-utils_ module for this use case:

```java
KeyPair sniKeyPair = KeyPairUtils.createKeyPair(2048);
X509Certificate cert = CertificateUtils.createTlsSniCertificate(sniKeyPair, subject);
```

Now use `cert` and `sniKeyPair` to let your web server respond to a SNI request to `subject`.

The challenge is completed when the CA was able to send the SNI request and get the correct certificate in return.

This shell command line may be helpful to test your web server configuration:

```shell
echo QUIT | \
  openssl s_client -servername $subject -connect $server_ip:443 | \
  openssl x509 -text -noout
```

It should return a certificate with `subject` set as `X509v3 Subject Alternative Name`.
