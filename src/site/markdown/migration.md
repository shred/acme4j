# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 2.0

_acme4j_ 2.0 fully supports the ACMEv2 protocol. Sadly, the ACMEv2 protocol is a major change.

There is no easy recipe to migrate your code to _acme4j_ 2.0. I recommend to have a look at the example, and read this documentation. Altogether, it shouldn't be too much work to update your code, though.

### "Malformed account ID in KeyID header"

If you try to use your old ACME v1 account location URL in ACME v2, you will get a "Malformed account ID in KeyID header" error. The easiest way to fix this is to register a new account **with your existing account key pair**. You will get your migrated account location URL in return.
