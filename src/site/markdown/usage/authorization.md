# Authorize your Domains

Once you have your account set up, you need to associate your domains with it. This is done by creating an `Authorization` object:

```java
Registration registration = ... // your Registration object

Authorization auth = registration.authorizeDomain("example.org");
```

The `Authorization` instance contains further details about how you can prove ownership of your domain. An ACME server offers combinations of different authorization methods, called `Challenge`s.

`Authorization` methods help you find the `Challenge` that fits best to your possibilities. Just pass all the challenge types that your software is able to accept to `findCombination()`, and it returns the shortest possible combination of `Challenge`s you have to perform.

In the following example, your software would be able to either perform a HTTP or DNS challenge, or both:

```java
Collection<Challenge> combination = auth.findCombination(
        Http01Challenge.TYPE, Dns01Challenge.TYPE);
```

The returned `combination` contains a single combination of challenges you would have to perform. If the combination consists of more than one challenge, you will have to perform _all of them_ in order to successfully authorize your domain. If `null` is returned, it means that none of your offered challenge types are acceptable to the CA.

If your software only implements a single challenge type, `findChallenge()` may be a little easier to use:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
```

It returns a properly casted `Challenge` object, or `null` if your challenge type was not acceptable.

The `Challenge` object provides the necessary data for a successful verification of your domain ownership. The kind of response depends on the challenge type (see the [documentation of challenges](../challenge/index.html)).

After you have performed the necessary steps to set up the response to the challenge (e.g. creating a file or modifying your DNS records), the ACME server is told to test your response:

```java
challenge.trigger();
```

Now you have to wait for the server to test your response and set the challenge status to `VALID`. The easiest way is to poll the status:

```java
while (challenge.getStatus() != Status.VALID) {
    Thread.sleep(3000L);
    challenge.update();
}
```

This is a very simple example. You should limit the number of loop iterations, and abort the loop when the status should turn to `INVALID`. If you know when the CA server actually requested your response (e.g. when you notice a HTTP request on the response file), you should start polling after that event.

`update()` may throw an `AcmeRetryAfterException`, giving an estimated time in `getRetryAfter()` for when the challenge is completed. You should then wait until that moment has been reached, before trying again. The challenge state is still updated when this exception is thrown.

As soon as all the necessary challenges are `VALID`, you have successfully associated the domain with your account.

If your final certificate will contain further domains or subdomains, repeat the authorization run with each of them.

## Update an Authorization

The server also provides an authorization URI. It can be retrieved from `Authorization.getLocation()`. You can recreate the `Authorization` object at a later time just by binding it to your `Session`:

```java
URI authUri = ... // Authorization URI

Authorization auth = Authorization.bind(session, authUri);
```

As soon as you invoke a getter, the `Authorization` object lazily loads the current server state of your authorization, including the domain name, the overall status, and an expiry date.

You can always invoke `update()` to read the current server state again. It may throw an `AcmeRetryAfterException`, giving an estimated time in `getRetryAfter()` for when all challenges are completed. The authorization state is still updated even when this exception is thrown. If you invoke `update()` for polling the authorization state, you should wait until the moment given in the exception has been reached before trying again.

## Deactivate an Authorization

It is possible to deactivate an `Authorization`, for example if you sell the associated domain.

```java
auth.deactivate();
```

## Restore a Challenge

Validating a challenge can take a considerable amount of time and is a candidate for asynchronous execution. This can be a problem if you need to keep the `Challenge` object for a later time or a different Java environment.

To recreate a `Challenge` object at a later time, all you need is to store the original object's `location` property:

```java
Challenge originalChallenge = ... // some Challenge instance
URI challengeUri = originalChallenge.getLocation();
```

Later, you restore the `Challenge` object by invoking `Challenge.bind()`.

```java
URI challengeUri = ... // challenge URI
Challenge restoredChallenge = Challenge.bind(session, challengeUri);
```

The `restoredChallenge` already reflects the current state of the challenge.
