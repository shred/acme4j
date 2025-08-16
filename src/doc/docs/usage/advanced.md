# Advanced Topics

## Change of TOS

If the CA changes the terms of service and requires an explicit agreement to the new terms, an `AcmeUserActionRequiredException` will be thrown. Its `getInstance()` method returns the URL of a human-readable web document that gives instructions about how to agree to the new terms of service (e.g. by clicking on a confirmation button).

Unfortunately, the `AcmeUserActionRequiredException` can be thrown at any time _acme4j_ is contacting the CA, and won't go away by itself.

There is no way to automatize this process. It requires human interaction, even on a Saturday night. Note that this is a limitation of the ACME protocol, not _acme4j_.

## Custom CSR

Usually _acme4j_ takes the hassle of creating a simple CSR for you. If you need more control over the CSR file, you can provide a PKCS#10 CSR file, either as `PKCS10CertificationRequest` instance or as DER formatted binary. The CSR must provide exactly the domains that you had passed to the `order()`, otherwise the finalization will fail on server side.

To create a CSR, you can use command like tools like `openssl` or Java frameworks like [Bouncy Castle](http://www.bouncycastle.org/java.html).

For your convenience, there is a [`CSRBuilder`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/util/CSRBuilder.html) that simplifies the CSR generation and should be sufficient for most use cases.

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.addDomain("www.example.org");
csrb.addDomain("m.example.org");
csrb.setOrganization("The Example Organization")
csrb.sign(domainKeyPair);

csrb.write(new FileWriter("example.csr"));  // Write to file

byte[] csr = csrb.getEncoded();  // Get a binary representation
```

The `CSRBuilder` also accepts IP addresses and `Identifier` for generating the CSR:

```java
CSRBuilder csrb = new CSRBuilder();
csrb.addIP(InetAddress.getByName("192.0.2.2"));
csrb.addIdentifier(Identifier.ip("192.0.2.3"));
csrb.sign(domainKeyPair);
```

The `CSRBuilder` is used internally for creating the CSR, and you can take influence on the generated CSR by using the `Order.execute(KeyPair domainKeyPair, Consumer<CSRBuilder> builderConsumer)` method.

## Domain Pre-Authorization

It is possible to proactively authorize a domain, without ordering a certificate yet. This can be useful to find out what challenges are requested by the CA to authorize a domain. It may also help to speed up the ordering process, as already completed authorizations do not need to be completed again when ordering the certificate in the near future.

```java
Account account = ... // your Account object
String domain = ...   // Domain name to authorize

Authorization auth = account.preAuthorize(Identifier.dns(domain));
```

!!! note
    Some CAs may not offer domain pre-authorization, `preAuthorizeDomain()` will then fail and throw an `AcmeNotSupportedException`. Some CAs may limit pre-authorization to certain domain types (e.g. non-wildcard) and throw an `AcmeServerException` otherwise.

To pre-authorize a domain for subdomain certificates as specified in [RFC 9444](https://tools.ietf.org/html/rfc9444), flag the `Identifier` accordingly using `allowSubdomainAuth()`:

```java
Account account = ... // your Account object
String domain = ...   // Domain name to authorize

Authorization auth = account.preAuthorize(Identifier.dns(domain).allowSubdomainAuth());
```

## Localized Error Messages

By default, _acme4j_ will send your system's default locale as `Accept-Language` header to the CA (with a fallback to any other language). If the language is supported by the CA, it will return localized error messages.

To select another language, use `Session.setLocale()`. The change will only affect that session, so you can have multiple sessions with different locale settings.

## Network Settings

You can use `Session.networkSettings()` to change some network parameters for the session.

* If a proxy must be used for internet connections, you can set a `ProxySelector` instance via `setProxySelector()`.
* To change network timeouts, use `setTimeout()`. The default timeout is 30 seconds. You can either increase the timeout for poor network connections, or reduce it to fail early on network errors. The change affects connection and read timeouts.
* If you need authentication (e.g. for the proxy), you can set an `Authenticator` via `setAuthenticator()`. Be careful here! Most code snippets I have found on the internet will send out the full proxy credentials to anyone who is asking. You should check `Authenticator.getRequestorType()` and make sure it is `RequestorType.PROXY` before sending the proxy credentials.
* _acme4j_ accepts HTTP `gzip` compression by default. If it should impede debugging, it can be disabled via `setCompressionEnabled(false)`.
