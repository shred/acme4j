# Connect to an ACME server

[`AcmeClientFactory.connect()`](../apidocs/org/shredzone/acme4j/AcmeClientFactory.html) creates an [`AcmeClient`](../apidocs/org/shredzone/acme4j/AcmeClient.html) and connects it to an ACME server.

The `connect()` method expects the URI of the ACME server's directory service, as it is documented by the CA. For example, this is how to connect to the _Let's Encrypt_ staging server:

```java
AcmeClient client =
    AcmeClientFactory.connect("https://acme-staging.api.letsencrypt.org/directory");
```

However, such an URI is hard to remember and might even change in the future. Java also does not accept the certificate used by the _Let's Encrypt_ server, so calls to the `AcmeClient` are likely to throw a certificate exception.

For this reason, special ACME URIs should be preferred:

```java
AcmeClient client = AcmeClientFactory.connect("acme://letsencrypt.org/staging");
```

 Instead of a generic provider, this call uses a special _Let's Encrypt_ provider that also accepts the _Let's Encrypt_ certificate.
