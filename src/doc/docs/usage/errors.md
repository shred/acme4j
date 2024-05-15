# Errors

The CA will send all errors as [RFC7807](https://datatracker.ietf.org/doc/html/rfc7807) problem documents. _acme4j_ parses these documents and provides a `Problem` representation of them.

The simplest way to handle the problem is to log the result of its `.toString()` method. It contains a summary of all important fields.

There are other methods that return machine- and human-readable details and subproblems. With `.asJSON()` you can also get a JSON representation of the full problem document, in case there are non-standard fields.

## Errors while Ordering

If your challenge has failed, you can retrieve the cause of the failure with `Challenge.getError()` or `Order.getError()`. It returns an `Optional` containing further details why the challenge has failed.

## Exceptions

`AcmeServerException` and its subclasses provide a `getProblem()` method that returns the `Problem` that caused the exception. The exception message also contains a summary of the problem.
