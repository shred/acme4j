# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 2.0

_acme4j_ 2.0 fully supports the ACMEv2 protocol. Sadly, the ACMEv2 protocol is a major change.

There is no easy recipe to migrate your code to _acme4j_ 2.0. I recommend to have a look at the example, and read this documentation. Altogether, it shouldn't be too much work to update your code, though.

## Migration from Version 2.0-SNAPSHOT (GitHub master branch)

* The `Session` object has been split into `Session` and `Login`. The `Session` now only tracks the communication, and does not need an account key pair any more.
* To get a `Login` to an existing `Account`, use `Session.login()` with the account key pair and account URL.
* If you create a new `Account` using the `AccountBuilder`, you must pass in the key pair via `AccountBuilder.useKeyPair()`.
* You can find all resource bind methods in `Login` now.
