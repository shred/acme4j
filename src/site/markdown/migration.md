# Migration Guide

With version 0.6, _acme4j_ underwent a massive change to the API.

This document will help you migrate your code to the latest API when coming from a pre-0.6 release. It should be a matter of a few minutes in most cases.

## What's different?

In previous versions, the resource classes like `Registration` or `Authorization` were plain data transport objects, and an `AcmeClient` was used for the actual server communication. Now, the resource classes communicate directly with the server. The result is an API that is more object oriented.

Instead of an `AcmeClient`, you need a `Session` object now. The `Session` is initialized with the ACME server URI and your account's key pair.

```java
KeyPair keyPair = ... // your account KeyPair
Session session = new Session("acme://letsencrypt.org/staging", keyPair);
```

Instead of creating a plain `Registration` object, you now bind it to the session.

```java
URI accountLocationUri = ... // your account's URI
Registration registration = Registration.bind(session, accountLocationUri);
```

You must know your account's location URI. Use a `RegistrationBuilder` if you do not know it, or if you want to register a new account:

```java
Registration registration;
try {
  // Try to create a new Registration...
  registration = RegistrationBuilder.bind(session).create();
} catch (AcmeConflictException ex) {
  // It failed because your key was already registered.
  // Retrieve the registration location URI from the exception.
  registration = Registration.bind(session, ex.getLocation());
}
```

Let me give an example of how to use the resource objects. To start an authorization process for a domain, we previously needed a `Registration` object, an `Authorization` object, and an `AcmeClient` instance. This is the old way:

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

Let's continue the example. We find and trigger a HTTP challenge. Previously, it worked like this:

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

Note that the `authorize()` method is not needed any more, and has been removed.

As a rule of thumb, you will find the action methods in one of the objects you previously passed as parameter to the `AcmeClient` method. For example, when you wrote `client.triggerChallenge(registration, challenge)`, you will find the new `trigger` method in either `registration` or `challenge` (here it's `challenge`).

The API has also been cleaned up, with many confusing setter methods being removed. If you should miss a setter method, you was actually not supposed to invoke it anyway.

## tl;dr

There is no `AcmeClient` any more, but only a `Session`. The `Session` is bound to the resource classes `Registration`, `Authorization`, `Challenge` and `Certificate`.

All action methods can now be found in one of the resource classes. They are easy to spot because they have a `throws AcmeException` clause.

## Why the change?

In previous versions, _acme4j_ used a client centric approach, with dumb data transport classes that only stored a mix of parameters and return values.

This approach turned out to have major disadvantages. For example, the data transport classes contained setter methods that were supposed to be used only by _acme4j_ itself. Some other setters had to be used by the library user, but only under certain circumstances. To make a long story short: The API was not self-explanatory about when to use what setters.

Also, the old API was too limited to reflect coming features of the ACME specifications. `AcmeClient` would soon become a bottleneck.

As _acme4j_ is still in beta state, I prefered to make a hard cut and do a major API makeover. Trying to maintain backward compatibility by all means would end up with an overly complicated library.

It took me a lot of time to refactor _acme4j_ and unclutter the API. I hope you like the change.
