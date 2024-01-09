# Session and Connection

Central part of the communication with the CA is a [`Session`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/Session.html) object. It is used to track the communication with the ACME server.

The first step is to create such a `Session` instance.

## Standard URIs

The `Session` constructor expects the URI of the ACME server's _directory_, as it is documented by the CA. For example, this is how to connect to the _Let's Encrypt_ staging server.

```java
Session session
    = new Session("https://acme-staging-v02.api.letsencrypt.org/directory");
```

The Session now knows where to locate the service endpoints. However, no actual connection to the server is done yet. The connection to the CA is handled later by a generic provider.

## ACME URIs

Such an URI is hard to remember and might even change in the future. For this reason, special ACME URIs should be preferred (if available):

```java
Session session = new Session("acme://letsencrypt.org/staging");
```
or
```java
Session session = new Session("acme://ssl.com/staging");
```

Instead of a generic provider, this call uses a specialized _Let's Encrypt_ provider.

The _Let's Encrypt_ staging server is meant to be used for testing purposes only. The issued certificates are functional, but as the issuer certificate is not known to browsers, it will lead to an error if the certificate is validated.

To use the _Let's Encrypt_ production server, you only need to change the ACME URI:

```java
Session session = new Session("acme://letsencrypt.org");
```
or to use the _SSL.com_ production server:
```java
Session session = new Session("acme://ssl.com");
```

## Metadata

CAs can provide metadata related to their ACME server. They are evaluated with the `session.getMetadata()` method.

```java
Metadata meta = session.getMetadata();

Optional<URI> tos = meta.getTermsOfService();
Optional<URL> website = meta.getWebsite();
```
