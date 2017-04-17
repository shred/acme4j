# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 0.10

Starting with version 0.10, _acme4j_ requires Java 8 or higher. This is also reflected in the API.

The most noticeable change is that the old `java.util.Date` has been replaced by the new `java.time` API in the entire project. If you don't want to migrate your code to the new API, you can use `Date.from()` and `Date.toInstant()` to convert between the different date objects, where necessary.

## Migration to Version 0.9

Version 0.9 brought many changes to the internal API. However, this is only relevant if you run your own CA and make own extensions to _acme4j_ (e.g. if you implement a proprietary `Challenge`). If you use _acme4j_ only for retrieving certificates, you should not notice any changes.

There is one exception: `Authorization.findCombinations()` previously returned `null` if it did not find a matching set of combinations. Now it returns an empty list instead, to avoid unnecessary `null` checks in your code. If you use this method, make sure your code correctly handles empty lists.

If you use `Authorization.findChallenge()`, no changes are necessary to your code.

## Migration to Version 0.6

With version 0.6, _acme4j_ underwent a major change to the API.

In previous versions, the resource classes like `Registration` or `Authorization` were plain data transport objects, and an `AcmeClient` was used for the actual server communication. Now, the resource classes communicate directly with the server. The result is an API that is more object oriented.

Instead of an `AcmeClient`, you need a `Session` object now. The `Session` is initialized with the ACME server URI and your account's key pair.

```java
KeyPair keyPair = ... // your account KeyPair
Session session = new Session("acme://letsencrypt.org/staging", keyPair);
```

Instead of creating a plain `Registration` object, you now bind it to the session.

```java
URL accountLocationUrl = ... // your account's URL
Registration registration = Registration.bind(session, accountLocationUrl);
```

You must know your account's location URL. Use a `RegistrationBuilder` if you do not know it, or if you want to register a new account:

```java
Registration registration;
try {
  // Try to create a new Registration...
  registration = new RegistrationBuilder().create(session);
} catch (AcmeConflictException ex) {
  // It failed because your key was already registered.
  // Retrieve the registration location URL from the exception.
  registration = Registration.bind(session, ex.getLocation());
}
```

Let me give an example of how to use the resource objects. To start an authorization process for a domain, we previously needed a `Registration` object, an `Authorization` object, and an `AcmeClient` instance.

This is the *old* way:

```java
AcmeClient client = ... // your ACME client
Registration registration = ... // your Registration

Authorization auth = new Authorization();
auth.setDomain("example.org");

client.newAuthorization(registration, auth);
```

Now, the `Registration` object takes care of everything:

```java
Registration registration = ... // your Registration

Authorization auth = registration.authorizeDomain("example.org");
```

As you can see, the authorization method that actually invokes the ACME server has moved from `AcmeClient` to `Registration`.

Let's continue the example. We find and trigger a HTTP challenge.

Previously, it worked like this:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
challenge.authorize(registration);
client.triggerChallenge(registration, challenge);
```

With the new API, it is more concise now:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
challenge.trigger();
```

Note that the `authorize()` method is not needed any more, and has been removed without replacement.

As a rule of thumb, you will find the action methods in one of the objects you previously passed as parameter to the `AcmeClient` method. For example, when you wrote `client.triggerChallenge(registration, challenge)`, you will find the new `trigger` method in either `registration` or `challenge` (here it's `challenge`).

The API has also been cleaned up, with many confusing setter methods being removed. If you should miss a setter method, you was actually not supposed to invoke it anyway.
