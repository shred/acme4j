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

## Metadata

Some CAs provide metadata related to their ACME server. This information can be retrieved via the `Session` object:

```java
Metadata meta = session.getMetadata();
URI website = meta.getWebsite();
```

`meta` is never `null`, even if the server did not provide any metadata. All of the `Metadata` getters are optional though, and may return `null` if the respective information was not provided by the server.

## Available Providers

In _acme4j_ these providers are available:

* [Let's Encrypt](./letsencrypt.html)
* [Pebble](./pebble.html)
