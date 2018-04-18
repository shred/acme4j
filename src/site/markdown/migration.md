# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 2.1

- This version adds [JSR 305](https://jcp.org/en/jsr/detail?id=305) annotations. If you use a null-safe language like Kotlin, or tools like SpotBugs, your code may fail to compile because of detected possible null pointer dereferences and unclosed streams. These are potential bugs that need to be resolved.

- In _acme4j_'s `JSON` class, all `as...()` getters now expect a value to be present. For optional values, use `JSON.Value.optional()` or `JSON.Value.map()`. This class is rarely used outside of _acme4j_ itself, so you usually won't need to change anything.

## Migration to Version 2.0

_acme4j_ 2.0 fully supports the ACMEv2 protocol. Sadly, the ACMEv2 protocol is a major change.

There is no easy recipe to migrate your code to _acme4j_ 2.0. I recommend to have a look at the example, and read this documentation. Altogether, it shouldn't be too much work to update your code, though.

### "Malformed account ID in KeyID header"

If you try to use your old ACME v1 account location URL in ACME v2, you will get a "Malformed account ID in KeyID header" error. The easiest way to fix this is to register a new account **with your existing account key pair**. You will get your migrated account location URL in return.
