# Authorize your Domains

Once you have your account set up, you need to associate your domain with it. This is done by using an `Authorization` data transfer object:

```java
Authorization auth = new Authorization();
auth.setDomain("example.org");

client.newAuthorization(registration, auth);
```

When `newAuthorization()` returns successfully, the `Authorization` instance contains further details about how you can prove ownership of your domain. An ACME server offers combinations of different authorization methods, called `Challenge`s.

`Authorization` methods help you find the `Challenge` that fits best to your possibilities. Just pass all the challenge types that your software is able to accept to `findCombination()`, and it returns the shortest possible combination of `Challenge`s you have to perform.

In the following example, your software would be able to either perform a HTTP or DNS challenge, or both:

```java
Collection<Challenge> combination = auth.findCombination(
        Http01Challenge.TYPE, Dns01Challenge.TYPE);
```

The returned `combination` contains a single combination of challenges you would have to perform. If the combination consists of more than one challenge, you would have to perform _all of them_ in order to successfully authorize your domain. If `null` is returned, it means that none of your offered challenge types are acceptable to the CA.

If your software only implements a single challenge type, `findChallenge()` may be a little easier to use:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
```

It returns a properly casted `Challenge` object, or `null` if your challenge type was not acceptable.

After you have found a challenge, you need to sign it with your `Registration` first:

```java
challenge.authorize(registration);
```

After signing the challenge, it provides the necessary data for a successful response to the challenge. The kind of response depends on the challenge type (see the [documentation of challenges](../challenge/index.html)). Some types may also require more data for authorizing the challenge.

After you have performed the necessary steps to set up the response to the challenge, the ACME server is told to test your response:

```java
client.triggerChallenge(registration, challenge);
```

Again, the call completes the `Challenge` transfer object with server side data like the current challenge status and a challenge URI.

Now you have to wait for the server to test your response and set the challenge status to `VALID`. The easiest way is to poll the status:

```java
while (challenge.getStatus() != Challenge.Status.VALID) {
    Thread.sleep(3000L);
    client.updateChallenge(registration, challenge);
}
```

This is a very simple example. You should limit the number of loop iterations, and abort the loop when the status should turn to `INVALID`. If you know when the CA server actually requested your response (e.g. when you notice a HTTP request on the response file), you should start polling after that event.

As soon as the challenge is `VALID`, you have successfully associated the domain with your account.

If your final certificate contains further domains or subdomains, repeat the authorization run with each of them.

## Update an Authorization

For each authorization, the server provides an URI where the status of the authorization can be queried. It can be retrieved from `Authorization.getLocation()` after `newAuthorization()` returned.

To get a status overview of your authorization and all challenges, create a new `Authorization` object and pass the location URI to the constructor:

```java
URI authUri = ... // Authorization URI
Authorization auth = new Authorization(authUri);
client.updateAuthorization(auth);
```

After that call, the `Authorization` object contains the current server state about your authorization, including the domain name, the overall status, and an expiry date.

## Deactivate an Authorization

It is possible to deactivate an Authorization, for example if you sell the associated domain.

```java
URI authUri = ... // Authorization URI
Authorization auth = new Authorization(authUri);
client.deactivateAuthorization(registration, auth);
```

## Restore a Challenge

Validating a challenge can take a considerable amount of time and is a candidate for asynchronous execution. This can be a problem if you need to keep the `Challenge` object for a later time or a different Java environment.

To recreate a `Challenge` object at a later time, all you need is to store the original object's `location` property:

```java
Challenge originalChallenge = ... // some Challenge instance
URI challengeUri = originalChallenge.getLocation();
```

Later, you pass this `challengeUri` to `restoreChallenge()`:

```java
URI challengeUri = ... // challenge URI
Challenge restoredChallenge = client.restoreChallenge(registration, challengeUri);
```

The `restoredChallenge` already reflects the current state of the challenge.
