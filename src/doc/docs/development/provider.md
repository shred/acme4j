# ACME Provider

Basically, it is possible to connect to any kind of ACME server just by connecting to the URL of its directory resource:

```java
Session session = new Session("https://acme-v02.api.letsencrypt.org/directory");
```

ACME providers are "plug-ins" to _acme4j_ that are specialized on a single CA. For example, the _Let's Encrypt_ provider offers URIs that are much easier to remember. The example above would look like this:

```java
Session session = new Session("acme://letsencrypt.org");
```

## Writing your own Provider

Every CA that provides an ACME server should also have an own `AcmeProvider`, and if it is just for the sake of a pretty `acme:` URI.

However, it is also possible to adapt the behavior of wide parts of _acme4j_ to special characteristics of the CA, just by overriding methods and extending classes.

A client provider implements the [`AcmeProvider`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/provider/AcmeProvider.html) interface, but usually it is easier to extend [`AbstractAcmeProvider`](../acme4j-client/apidocs/org.shredzone.acme4j/org/shredzone/acme4j/provider/AbstractAcmeProvider.html) and implement only these two methods:

* `accepts(URI)` checks if the client provider is accepting the provided URI. Usually it would be an URI like `acme://example.com`. Note that the `http` and `https` schemes are reserved for the generic provider and cannot be used by other providers.
* `resolve(URI)` parses the URI and returns the corresponding URL of the directory service.

The `AcmeProvider` implementation needs to be registered with Java's `ServiceLoader`. In the `META-INF/services` path of your project, create a file `org.shredzone.acme4j.provider.AcmeProvider` and write the fully qualified class name of your implementation into that file. If you use Java modules, there must also be a `provides` section in your `module-info.java`, e.g.:

```java
provides org.shredzone.acme4j.provider.AcmeProvider
    with org.example.acme.provider.MyAcmeProvider;
```

When _acme4j_ tries to connect to an acme URI, it first invokes the `accepts(URI)` method of all registered `AcmeProvider`s. Only one of the providers must return `true` for a successful connection. _acme4j_ then invokes the `resolve(URI)` method of that provider, and connects to the directory URL that is returned.

The connection fails if no or more than one `AcmeProvider` implementation accepts the acme URI.

## Certificate Pinning

The standard Java mechanisms are used to verify the HTTPS certificate provided by the ACME server. To pin the certificate, or use a self-signed certificate, override the `createHttpConnector()` method of `AbstractAcmeProvider` and return a subclassed `HttpConnector` class that modifies the `HttpURLConnection` as necessary.

## Individual Challenges

If your ACME server provides challenges that are not specified in the ACME protocol, there should be an own `Challenge` implementation for each of your challenge, by extending the [`Challenge`](../apidocs/org/shredzone/acme4j/challenge/Challenge.html) class.

In your `AcmeProvider` implementation, override the `createChallenge(Login, JSON)` method so it returns a new instance of your `Challenge` implementation when your individual challenge type is requested. All other types should be delegated to the super method.

## Amended Directory Service

To override single entries of an ACME server's directory, or to use a static directory, override the `directory(Session, URI)` method, and return a `JSON` of all available resources and their respective URL.

## Adding your Provider to _acme4j_

After you completed your provider code, you can send in a pull request and apply for inclusion in the _acme4j_ code base.

These preconditions must be met:

* Your provider's source code must be published under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
* The source code of your ACME server must be publicly available under an [OSI compliant license](https://opensource.org/licenses/alphabetical).
* To avoid name conflicts, the `acme:` URI used must have the official domain name of your service as domain part.
* You have the permission of all trademark holders involved, to use their trademarks in the source codes, package names, and the acme URI.

The _acme4j_ development team reserves the right to reject your pull request, without giving any reason.

If you cannot meet these preconditions (or if your pull request was rejected), you can publish a JAR package of your _acme4j_ provider yourself. Due to the plug-in nature of _acme4j_ providers, it is sufficient to have that package in the Java classpath at runtime. There is no need to publish the source code.
