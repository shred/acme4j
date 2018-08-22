# tls-alpn-01 Challenge

With the `tls-alpn-01` challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a request with a specific self-signed cert utilizing the ALPN extension.

<div class="alert alert-info" role="alert">

This challenge is not part of the ACME specifications. It is specified [in a separate IETF document](https://tools.ietf.org/html/draft-ietf-acme-tls-alpn) and is still work in progress.
</div>

`TlsAlpn01Challenge` provides a byte array called `acmeValidation`:

```java
TlsAlpn01Challenge challenge = auth.findChallenge(TlsAlpn01Challenge.TYPE);

byte[] acmeValidation = challenge.getAcmeValidation();
```

You need to create a self-signed certificate with the domain to be validated set as the only _Subject Alternative Name_. The `acmeValidation` must be set as DER encoded `OCTET STRING` extension with the object id `1.3.6.1.5.5.7.1.31`. It is required to set this extension as critical.

After that, configure your web server so it will use this certificate on an incoming TLS request having the SNI `subject` and the ALPN protocol `acme-tls/1`.

The `TlsAlpn01Challenge` class does not generate a self-signed certificate, as it would require _Bouncy Castle_. However, there is a utility method in the _acme4j-utils_ module for this use case:

```java
String subject = auth.getDomain();
KeyPair certKeyPair = KeyPairUtils.createKeyPair(2048);

X509Certificate cert = CertificateUtils.
    createTlsAlpn01Certificate(certKeyPair, subject, acmeValidation);
```

Now use `cert` and `certKeyPair` to let your web server respond to TLS requests containing an ALPN extension with the value `acme-tls/1` and a SNI extension containing `subject`.

<div class="alert alert-info" role="alert">
The request is sent to port 443 only. If your domain has multiple IP addresses, the CA randomly selects one of them. There is no way to choose a different port or a fixed IP address.
</div>
