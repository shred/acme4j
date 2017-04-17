# ACME Provider

Basically, it is possible to connect to any kind of ACME server just by connecting to the URI of its directory resource:

```java
Session session = new Session("https://acme-v01.api.letsencrypt.org/directory", accountKeyPair);
```

ACME providers are "plug-ins" to _acme4j_ that are specialized on a single CA. For example, the _Let's Encrypt_ provider offers URIs that are much easier to remember. The example above would look like this:

```java
Session session = new Session("acme://letsencrypt.org", accountKeyPair);
```

## Writing an own Provider

Every CA that provides an ACME server should also have an own `AcmeProvider`, and if it is just for the sake of a pretty `acme:` URI.

However, it is also possible to adapt the behavior of wide parts of _acme4j_ to special characteristics of the CA, just by overriding methods and extending classes.

A client provider implements the [`AcmeProvider`](./apidocs/org/shredzone/acme4j/provider/AcmeProvider.html) interface, but usually it is easier to extend [`AbstractAcmeProvider`](./apidocs/org/shredzone/acme4j/provider/AbstractAcmeProvider.html) and implement only these two methods:

* `accepts(URI)` checks if the client provider is accepting the provided URI. Usually it would be an URI like `acme://example.com`. Note that the `http` and `https` schemes are reserved for the generic provider and cannot be used by other providers.
* `resolve(URI)` parses that URI and returns the corresponding URL of the directory service.

The `AcmeProvider` implementation needs to be registered with Java's `ServiceLoader`. In the `META-INF/services` path of your project, create a file `org.shredzone.acme4j.provider.AcmeProvider` and write the fully qualified class name of your implementation into that file.

When _acme4j_ tries to connect to an acme URI, it first invokes the `accepts(URI)` method of all registered `AcmeProvider`s. Only one of the providers must return `true` for a successful connection. _acme4j_ then invokes the `resolve(URI)` method of that provider, and connects to the directory URL that is returned.

The connection fails if none or more than one `AcmeProvider` implementations `accept` the acme URI.

## Certificate Pinning

Client providers may verify the HTTPS certificate provided by the ACME server.

To do so, override the `createHttpConnector()` method of `AbstractAcmeProvider` and return a subclassed `HttpConnector` class that modifies the `HttpURLConnection` as required.

## Individual Challenges

If your ACME server provides challenges that are not specified in the ACME protocol, there should be an own `Challenge` implementation for each of your challenge, by extending the [`Challenge`](./apidocs/org/shredzone/acme4j/challenge/Challenge.html) class.

In your `AcmeProvider` implementation, override the `createChallenge(Session, String)` method so it returns a new instance of your `Challenge` implementation when your individual challenge type is requested. All other types should be delegated to the super method.

## No directory service

An ACME server may not provide a directory service, for example when fixed URIs are to be used.

In this case, override the `directory(Session, URI)` method, and return a `JSON` of all available resources and their respective URI.
