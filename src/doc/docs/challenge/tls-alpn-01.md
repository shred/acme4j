# tls-alpn-01 Challenge

With the `tls-alpn-01` challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a request with a specific self-signed cert utilizing the ALPN extension. This challenge is specified in [RFC 8737](https://tools.ietf.org/html/rfc8737).

You need to create a self-signed certificate with the domain to be validated set as the only _Subject Alternative Name_. The byte array provided by `challenge.getAcmeValidation()` must be set as DER encoded `OCTET STRING` extension with the object id `1.3.6.1.5.5.7.1.31`. It is required to set this extension as critical.

_acme4j_ does the heavy lifting for you though, and provides a certificate that is ready to use. It is valid for 7 days, which is ample of time to perform the validation.

```java
TlsAlpn01Challenge challenge = auth.findChallenge(TlsAlpn01Challenge.class);
Identifier identifier = auth.getIdentifier();
KeyPair certKeyPair = KeyPairUtils.createKeyPair(2048);

X509Certificate cert = challenge.createCertificate(certKeyPair, identifier);
```

Now use `cert` and `certKeyPair` to let your web server respond to TLS requests containing an ALPN extension with the value `acme-tls/1` and a SNI extension containing your subject (`identifier`).

When the validation is completed, the `cert` and `certKeyPair` are not used anymore and can be disposed.

!!! note
    The request is sent to port 443 only. If your domain has multiple IP addresses, the CA randomly selects some of them. There is no way to choose a different port or a fixed IP address.

Your server should be able to handle multiple requests to the challenge. The ACME server may check your response multiple times, and from different IPs. Also keep your response available until the `Authorization` status has changed to `VALID` or `INVALID`.
