# Exceptions

_acme4j_ methods can throw a number of exceptions. All exceptions are derived from `AcmeException` and are checked exceptions. Only `AcmeLazyLoadingException` and `AcmeProtocolException` are runtime exceptions.

```text
Exception
├ AcmeException
│ ├ AcmeNetworkException
│ ├ AcmeRetryAfterException
│ └ AcmeServerException
│   ├ AcmeRateLimitedException
│   ├ AcmeUnauthorizedException
│   └ AcmeUserActionRequiredException
└ RuntimeException
  ├ AcmeLazyLoadingException
  └ AcmeProtocolException
    └ AcmeNotSupportedException
```

## AcmeException

This is the root class of all checked _acme4j_ exceptions.

## AcmeNetworkException

This is an `AcmeException` that is thrown on generic network errors during communication (e.g. network timeout).

The exception provides the causing `IOException`.

## AcmeRetryAfterException

This `AcmeException` shows that a server-side process has not been completed yet, and gives an estimation when the process might be completed.

It can only be thrown when invoking `update()`. However, it is preferred to invoke `fetch()`, which returns the retry-after instant directly, instead of throwing this exception.

!!! note
    The internal state of the resource is still updated.

The given estimation is only a proposal. This exception can be safely ignored. However, an earlier attempt to update the state will likely throw this exception again.

## AcmeServerException

An `AcmeException` that is thrown when the server responded with an error. The cause of the error is returned as `Problem` object.

A few special cases are throwing a subclass exception, which is easier to handle.

## AcmeRateLimitedException

This `AcmeServerException` shows that the client has exceeded a rate limit of the server, and the request was denied because of that.

The exception provides a `Problem` instance that further explains what rate limit has been exceeded. Optionally it also provides an `Instant` when the request is expected to succeed again. It also provides `URL`s to human-readable documents with further information about the rate limit.

## AcmeUnauthorizedException

An `AcmeServerException` that indicates that the client has insufficient permissions for the attempted request. For example, this exception is thrown when an account tries to access a resource that belongs to a different account.

## AcmeUserActionRequiredException

This `AcmeServerException` is thrown when an user action is required. The most likely reason is that the Terms of Service have been changed and must be confirmed before proceeding.

The exception provides a `Problem` object with a detailed reason, a link to a web page with further instructions to be taken by a human, and an optional link to the new Terms of Service.

## AcmeLazyLoadingException

This is a runtime exception that is thrown when an `AcmeException` occurs while a resource lazily tries to update its current state from the server.

After construction, all [resources](persistence.md) do not hold the state of the resource yet. For this reason, it is cheap to construct resources, as it does not involve network traffic.

To fetch the current state of the resource, `update()` can be invoked. In case of an error, the `update()` method throws a checked `AcmeException`.

All getter methods of a resource invoke `update()` implicitly if the current state is unknown. However, it would make usage much more complex if every getter could throw the checked `AcmeException`. For this reason, the getters wrap the `AcmeException` into a runtime `AcmeLazyLoadingException`.

If you want to avoid this exception to be thrown, you can invoke `update()` on the resource, and handle the `AcmeException` there in a single place. After that, the getters won't throw an `AcmeLazyLoadingException` anymore.

The exception returns the resource type, the resource location, and the `AcmeException` that was thrown.

## AcmeProtocolException

This is a runtime exception that is thrown if the server response was unexpected and violates the RFC. _acme4j_ was unable to parse the response properly.

An example would be that the server returned an invalid JSON structure that could not be parsed.

## AcmeNotSupportedException

This is an `AcmeProtocolException` that is thrown if the server does not support the requested feature. This can be because the feature is optional, or because the server is not fully RFC compliant.

The exception provides a description of the feature that was missing.
