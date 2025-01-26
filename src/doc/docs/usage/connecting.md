# Session and Connection

Central part of the communication with the CA is a [`Session`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/Session.html) object. It is used to track the communication with the ACME server.

The first step is to create such a `Session` instance.

## Standard URIs

The `Session` constructor expects the URI of the ACME server's _directory_, as it is documented by the CA. This is how to connect to a fictional example staging server:

```java
Session session
    = new Session("https://acme-staging-v02.api.example.org/directory");
```

The Session now knows where to locate the service endpoints. However, no actual connection to the server is done yet. The connection to the CA is handled later by a generic provider.

## ACME URIs

Such a URI is hard to remember and might even change in the future. For this reason, special ACME connection URIs should be preferred. These special ACME URIs look like this:

```java
Session session = new Session("acme://example.org/staging");
```

Instead of a generic provider, this call uses a provider that is specialized to the CA.

!!! note
    <span style="font-size:120%">**→ [Find the ACME Connection URI of your CA here!](../ca/index.md) ←**</span>

    If your CA is not listed there, it might still provide a JAR file with a proprietary provider that you can add to the classpath.

    **You can always use the standard URI (as mentioned above) to connect to any [RFC 8555](https://tools.ietf.org/html/rfc8555) compliant CA.**

A staging server is meant to be used for testing purposes only. The issued certificates are functional, but as the issuer certificate is not known to browsers, it will lead to an error if the certificate is validated.

To use the production server, you only need to change the ACME URI:

```java
Session session = new Session("acme://example.org");
```

## Metadata

CAs can provide metadata related to their ACME server. They are evaluated with the `session.getMetadata()` method.

```java
Metadata meta = session.getMetadata();

Optional<URI> tos = meta.getTermsOfService();
Optional<URL> website = meta.getWebsite();
```
