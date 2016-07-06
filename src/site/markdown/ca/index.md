# Certificate Authorities

_acme4j_ should support any CA providing an ACME server.

It is always possible to connect to an ACME server by passing in the CA's resource directory URI:

```java
Session session =
    new Session("https://acme-staging.api.letsencrypt.org/directory", accountKeyPair);
```

For some CAs there are also more specific ACME providers available via `acme` schemed URIs:

```java
Session session =
    new Session("acme://letsencrypt.org/staging", accountKeyPair);
```

Connecting via `acme` URI should always be preferred over using the directory URL.

## Available Providers

In _acme4j_ these providers are available:

* [Let's Encrypt](./letsencrypt.html)
