# ACME Client Provider

Basically, it is possible to connect to any kind of ACME server just by connecting to the URI of its directory resource:

```java
AcmeClient client =
    AcmeClientFactory.connect("https://acme-v01.api.letsencrypt.org/directory");
```

ACME client providers are "plug-ins" to _acme4j_ that are specialized on a single CA. For example, the _Let's Encrypt_ client provider offers connection URIs that are much easier to remember. Opening a connection like in the example above looks like this:

```java
AcmeClient client = AcmeClientFactory.connect("acme://letsencrypt.org");
```

## Writing an own Client Provider

Every CA that provides an ACME server should also have an own Client Provider, and if it is just for the sake of a pretty `acme:` URI.

However, it is also possible to adapt the behavior of wide parts of _acme4j_ to special characteristics of the CA, just by overriding methods and extending classes.

A client provider implements the [`AcmeClientProvider`](./apidocs/org/shredzone/acme4j/provider/AcmeClientProvider.html) interface, but usually it is easier to extend [`AbstractAcmeClientProvider`](./apidocs/org/shredzone/acme4j/provider/AbstractAcmeClientProvider.html) and implement only these two methods:

* `accepts(URI)` checks if the client provider is accepting the provided URI. Usually it would be an URI like `acme://example.com`. Note that the `http` and `https` schemes are reserved for the generic provider and cannot be used by client providers.
* `resolve(URI)` parses that URI and returns the corresponding URI of the directory service.

The `AcmeClientProvider` implementation needs to be registered with Java's `ServiceLoader`. In the `META-INF/services` path of your project, create a file `org.shredzone.acme4j.provider.AcmeClientProvider` and write the fully qualified class name of your implementation into that file.

When _acme4j_ tries to connect to an acme URI, it first invokes the `accepts(URI)` method of all registered `AcmeClientProvider`s. Only one of the providers must return `true` for a successful connection. _acme4j_ then invokes the `resolve(URI)` method of that provider, and connects to the directory URI that is returned.

The connection fails if none or more than one `AcmeClientProvider` implementations `accept` the acme URI.

## Certificate Pinning

Client providers may verify the HTTPS certificate provided by the ACME server.

To do so, override the `createHttpConnector()` method of `AbstractAcmeClientProvider` and return a subclassed `HttpConnector` class that modifies the `HttpURLConnection` as required.

The source code of the [_Let's Encrypt_ provider](./apidocs/org/shredzone/acme4j/provider/letsencrypt/package-summary.html) gives an example of how to do that.

## Individual Challenges

If your ACME server provides challenges that are not specified in the ACME protocol, there should be an own `Challenge` implementation for each of your challenge, by either implementing the [`Challenge`](./apidocs/org/shredzone/acme4j/challenge/Challenge.html)
interface or (more conveniently) extending the [`GenericChallenge`](./apidocs/org/shredzone/acme4j/challenge/GenericChallenge.html) class.

In your `AcmeClientProvider` implementation, override the `createChallenge(String)` method so it returns a new instance of your `Challenge` implementation when your individual challenge type is requested. All other types should be delegated to the super method.

## No directory service

An ACME server may not provide a directory service, for example when fixed URIs are to be used.

In this case, extend `GenericAcmeClient` and override the `resourceUri(Resource)` method. It should return the URI of the given resource.

Your `AcmeClientProvider`'s `connect(URI)` method would then return a new instance of your `GenericAcmeClient` class. Just use `null` as your directory URI.
