# Creating a Session

Central part of the communication is a [`Session`](../apidocs/org/shredzone/acme4j/Session.html) object, which contains the URI of the target ACME server, and your account key pair. The ACME server identifies your account by your public key, and verifies that your requests are signed with a matching private key. Your private key is _never_ transferred to the ACME server!

The first step is to create a `Session` instance. The `Session` tracks the communication with your account at the ACME server. If you want to access multiple accounts, you will need a separate `Session` instance for each of them.

```java
KeyPair keyPair = ... // your key pair
URI acmeServerUri = ... // uri of the ACME server

Session session = new Session(acmeServerUri, keyPair);
```

The `Session` constructor expects the URI of the ACME server's directory service, as it is documented by the CA. For example, this is how to connect to the _Let's Encrypt_ staging server:

```java
Session session
    = new Session("https://acme-staging.api.letsencrypt.org/directory", keyPair);
```

However, such an URI is hard to remember and might even change in the future. Also, Java accepts the certificate used by the _Let's Encrypt_ server since JDK 8u101, calls to their servers are likely to throw a certificate exception on older versions.

For this reason, special ACME URIs should be preferred:

```java
Session session = new Session("acme://letsencrypt.org/staging", keyPair);
```

Instead of a generic provider, this call uses a special _Let's Encrypt_ provider that also accepts the _Let's Encrypt_ certificate.

Now that you have a `Session` object, you can use it to bind ACME resource objects. For example, this is the way to get an `Account` object to an existing account:

```java
URL accountLocationUrl = ... // your account's URL, as returned by Account.getLocation()

Account account = Account.bind(session, accountLocationUrl);
```

You can create any of the resource objects `Account`, `Authorization`, `Challenge` and `Certificate` like that, as long as you know the corresponding resource URL. To get the resource URL, use the `getLocation()` method.

## Serialization

All resource objects are serializable, so the current state of the object can be frozen by Java's serialization mechanism.

However the `Session` the object is bound with is _not_ serialized! This is because the `Session` object contains a copy of your private key. Not serializing it prevents that you unintentionally reveal your private key in a place with lowered access restrictions.

This means that a deserialized object is not bound to a `Session` yet. It is required to rebind it to a `Session`, by invoking its `rebind()` method.
