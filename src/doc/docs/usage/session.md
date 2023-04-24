# Creating a Session

Central part of the communication is a [`Session`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/Session.html) object. A session is used to track the communication with the ACME server.

The first step is to create a `Session` instance. The `Session` constructor expects the URI of the ACME server's directory service, as it is documented by the CA. For example, this is how to connect to the _Let's Encrypt_ staging server:

```java
Session session
    = new Session("https://acme-staging-v02.api.letsencrypt.org/directory");
```

However, such an URI is hard to remember and might even change in the future. For this reason, special ACME URIs should be preferred:

```java
Session session = new Session("acme://letsencrypt.org/staging");
```

Instead of a generic provider, this call uses a special _Let's Encrypt_ provider.

The _Let's Encrypt_ staging server is meant to be used for testing purposes only. The issued certificates are functional, but as the issuer certificate is not known to browsers, it will lead to a certificate error. Later you only need to change the ACME URI in order to use the _Let's Encrypt_ production server.

```java
Session session = new Session("acme://letsencrypt.org");
```

## Metadata

Some CAs provide metadata related to their ACME server:

```java
Metadata meta = session.getMetadata();
URI tos = meta.getTermsOfService();
URL website = meta.getWebsite();
```

`meta` is never `null`, even if the server did not provide any metadata. All of the `Metadata` getters are optional though, and may return `null` if the respective information was not provided by the server.

## Locale

`Session.setLocale()` allows to select a different locale. Errors will be returned in that language, if supported by the CA.

By default, the system's default locale is used.

## Network Settings

You can use `Session.networkSettings()` to change some network parameters for the session.

* If a proxy must be used for internet connections, you can set a `ProxySelector` instance via `setProxySelector()`.
* To change network timeouts, use `setTimeout()`. The default timeout is 10 seconds. You can either increase the timeout on poor network connections, or reduce it to fail early on network errors.
* If you need authentication (e.g. for the proxy), you can set an `Authenticator` via `setAuthenticator()`. Be careful here! Most code snippets I have found on the internet will send out the proxy credentials to anyone who is asking. You should check `Authenticator.getRequestorType()` and make sure it is `RequestorType.PROXY` before sending the proxy credentials.
* _acme4j_ accepts HTTP `gzip` compression by default. If it should impede debugging, it can be disabled via `setCompressionEnabled(false)`.
