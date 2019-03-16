# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 2.7

- There are no breaking API changes in this version, except of the removal of `CertificateUtils.createTlsAlpn01Certificate(KeyPair, String, byte[])` which has been marked as deprecated in v2.6.

- The ACME draft has been finalized and is now called [RFC 8555](https://tools.ietf.org/html/rfc8555). For this reason, the _acme4j_ API is now stable. There won't be breaking changes to the public API in the future, unless absolutely necessary.

## Migration to Version 2.6

- If you use the `tls-alpn-01` challenge and `CertificateUtils.createTlsAlpn01Certificate()` for generating its test certificate, you need to pass the domain name as an `Identifier` object instead of a `String` now. You can use `Identifier.dns(subject)` for conversion. You can also use `Authorization.getIdentifier()` to get the `Identifier` object immediately.

## Migration to Version 2.5

- The GET compatibility mode has been removed. It also means that the `postasget=false` parameter is ignored from now on. If you need it to connect to your ACME server, do not update to this version until your ACME server has been fixed to support ACME draft 15.

<div class="alert alert-info" role="alert">

I recommend to update to this _acme4j_ version as soon as possible! _Let's Encrypt_ has [announced a sunset date for GET requests](https://community.letsencrypt.org/t/acme-v2-scheduled-deprecation-of-unauthenticated-resource-gets/74380) on November 1st, 2019. _acme4j_ v2.4 and older will break after that date!
</div>

## Migration to Version 2.4

- There was a major change in ACME draft 15. If you use _acme4j_ in a common way, it will transparently take care of everything in the background, so you won't even notice the change.

  However, if you connect to a different ACME server than Boulder (Let's Encrypt) or Pebble, you may now get strange errors from the server if it does not support the `POST-as-GET` requests of draft 15 yet. In that case, you can add a `postasget=false` parameter to the ACME server URI (e. g. `"https://localhost:15000/dir?postasget=false"`). Note that this is only a temporary workaround. It will be removed in a future version. Ask the server's CA to add support for ACME draft 15.

- The `AcmeProvider.connect()` method now gets the ACME server URI as parameter. It allows to add query parameters to the server URI that change the behavior of the resulting connection. If you have implemented your own AcmeProvider, just change the method's signature to `Connection connect(URI serverUri)`, and ignore the parameter value.

## Migration to Version 2.3

- `Authorization.getDomain()`, `Order.getDomains()` and `Problem.getDomain()` are deprecated now, and will be removed in version 2.4. If you use these methods, use `getIdentifier()` (or `getIdentifiers()`) to get an `Identifier` object, then invoke `Identifier.getDomain()` to get the domain name.

## Migration to Version 2.1

- This version adds [JSR 305](https://jcp.org/en/jsr/detail?id=305) annotations. If you use a null-safe language like Kotlin, or tools like SpotBugs, your code may fail to compile because of detected possible null pointer dereferences and unclosed streams. These are potential bugs that need to be resolved.

- In _acme4j_'s `JSON` class, all `as...()` getters now expect a value to be present. For optional values, use `JSON.Value.optional()` or `JSON.Value.map()`. This class is rarely used outside of _acme4j_ itself, so you usually won't need to change anything.

## Migration to Version 2.0

_acme4j_ 2.0 fully supports the ACMEv2 protocol. Sadly, the ACMEv2 protocol is a major change.

There is no easy recipe to migrate your code to _acme4j_ 2.0. I recommend to have a look at the example, and read this documentation. Altogether, it shouldn't be too much work to update your code, though.

### "Malformed account ID in KeyID header"

If you try to use your old ACME v1 account location URL in ACME v2, you will get a "Malformed account ID in KeyID header" error. The easiest way to fix this is to register a new account **with your existing account key pair**. You will get your migrated account location URL in return.
