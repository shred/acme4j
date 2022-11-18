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

_acme4j_ uses a standard `HttpURLConnection` for HTTP connections. You can use `Session.networkSettings()` to change some network parameters for the session.

* If a proxy must be used for internet connections, you can set a `Proxy` instance via `setProxy()`. An alternative is to use the system properties `https.proxyHost` and `https.proxyPort` to globally set a proxy for the Java process.
* To change network timeouts, use `setTimeout()`. The default timeout is 10 seconds. You can either increase the timeout on poor network connections, or reduce it to fail early on network errors.

If the proxy needs authentication, you need to set a default `Authenticator`. Be careful: Most code snippets I have found on the internet will send out the proxy credentials to anyone who is asking. See [this blog article](https://rolandtapken.de/blog/2012-04/java-process-httpproxyuser-and-httpproxypassword) for a good way to implement a proxy `Authenticator`.
