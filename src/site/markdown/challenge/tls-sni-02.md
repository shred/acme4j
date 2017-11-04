# tls-sni-02 Challenge

> **NOTE:** According to the ACME specifications, this challenge will replace [tls-sni-01](./tls-sni-01.html). However, _Let's Encrypt_ does not currently support `tls-sni-02`. To be on the safe side, request both challenges and process the one that is returned.

With the `tls-sni-02` challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a SNI request with a specific self-signed cert.

`TlsSni02Challenge` provides a subject and a key-authorization domain:

```java
TlsSni02Challenge challenge = auth.findChallenge(TlsSni02Challenge.TYPE);

String subject = challenge.getSubject(); // SAN-A
String sanB = challenge.getSanB();       // SAN-B
```

`subject` and `sanB` are basically domain names formed like in this example:

```
5bf0b9908ed73bc53ed3327afa52f76b.0a4bea00520f0753f42abe0bb39e3ea8.token.acme.invalid
14e2350a04434f93c2e0b6012968d99d.ed459b6a7a019d9695609b8514f9d63d.ka.acme.invalid
```

You need to create a self-signed certificate with both `subject` and `sanB` set as _Subject Alternative Name_. After that, configure your web server so it will use this certificate on a SNI request to `subject`.

The `TlsSni02Challenge` class does not generate a self-signed certificate, as it would require _Bouncy Castle_. However, there is a utility method in the _acme4j-utils_ module for this use case:

```java
KeyPair sniKeyPair = KeyPairUtils.createKeyPair(2048);
X509Certificate cert = CertificateUtils.createTlsSni02Certificate(sniKeyPair, subject, sanB);
```

Now use `cert` and `sniKeyPair` to let your web server respond to SNI requests to `subject`. The CA is not allowed to reveal `sanB`, so it will not perform SNI requests to that domain.

The challenge is completed when the CA was able to send the SNI request and get the correct certificate in return.

Note that the request is sent to port 443 only. There is no way to choose a different port, for security reasons. This is a limitation of the ACME protocol, not of _acme4j_.

This shell command line may be helpful to test your web server configuration:

```shell
echo QUIT | \
  openssl s_client -servername $subject -connect $server_ip:443 | \
  openssl x509 -text -noout
```

It should return a certificate with both `subject` and `sanB` set as `X509v3 Subject Alternative Name`.
