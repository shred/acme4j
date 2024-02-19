# Migration Guide

This document will help you migrate your code to the latest _acme4j_ version.

## Migration to Version 3.2.0

- Starting with this version, the `CSRBuilder` won't add the first domain as common name automatically. This permits the issuance of very long domain names, and should have no negative impact otherwise, as this field is usually ignored by CAs anyway. If you should encounter a problem here, you can use `CSRBuilder.setCommonName()` to set the first domain as common name manually. Discussion see [here](https://community.letsencrypt.org/t/questions-re-simplifying-issuance-for-very-long-domain-names/207925/11).
- acme4j was updated to support the latest [draft-ietf-acme-ari-03](https://www.ietf.org/archive/id/draft-ietf-acme-ari-03.html) now. It is a breaking change! If you use ARI, make sure your server supports the latest draft before updating to this version of acme4j.
- `Certificate.markAsReplace()` has been removed, because this method is not supported by [draft-ietf-acme-ari-03](https://www.ietf.org/archive/id/draft-ietf-acme-ari-03.html) anymore. To mark an existing certificate as replaced, use the new method `OrderBuilder.replaces()` now.
- `Certificate.getCertID()` is not needed in the ACME context anymore. This method has been marked as deprecated. In a future version of acme4j, it will be removed without replacement. Refer to the source code to see how the certificate ID is computed.

## Migration to Version 3.0.0

Although acme4j has made a major version bump, the migration of your code should be done in a few minutes for most of you.

- The `acme4j-utils` module has been removed, and its classes moved into `acme4j-client` module. If you have used it before, just remove the dependency. If your project has a `module-info.java` file, remember to remove the `requires org.shredzone.acme4j.utils` line there as well.
- All `@Nullable` return values have been removed where possible. Returned collections may now be empty, but are never `null`. Most of the other return values are now either `Optional`, or are throwing an exception if more reasonable. If your code fails to compile because the return type has changed to `Optional`, you could simply add `.orElse(null)` to emulate the old behavior. But often your code will reveal a better way to handle the former `null` pointer instead.
- `acme4j-client` now depends on Bouncy Castle, so you might need to register it as security provider at the start of your code:
  ```java
  Security.addProvider(new BouncyCastleProvider());
  ```

What you might also need to know:

- A new `AcmeNotSupportedException` is thrown if a feature is not supported by the server. It is a subclass of the `AcmeProtocolException` runtime exception.
- Starting with _acme4j_ v3, we will require the smallest Java SE LTS version that is still receiving premier support according to the [Oracle Java SE Support Roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html). At the time of writing, these are Java 11 and Java 17, so _acme4j_ requires Java 11 starting from now. With the prospected release of Java 21 (LTS) in September 2023, we will move to Java 17, and so on. If you still need Java 8, you can use _acme4j_ v2. However it won't receive updates anymore, except of security related fixes.
- _acme4j_ now uses the new `java.net.http` client. Due to limitations of the API, HTTP errors are only thrown with the error code, but the respective error message is missing. If you checked the error message in your unit tests, be prepared that they might fail now.
- acme4j now accepts HTTP gzip compression. It is enabled by default, but if it causes problems or impedes debugging, it can be disabled in the `NetworkSettings` or by setting the `org.shredzone.acme4j.gzip_compression` system property to `false`.
- All deprecated methods have been removed.

## Migration to Version 2.16

- In `acme4j-smime`, the `EmailProcessor.smimeMessage()` method is now deprecated. Use either `EmailProcessor.signedMessage()`, or `EmailProcessor.builder()` if you need custom verification configuration (e.g. an own truststore).
- In `acme4j-smime`, major parts of the S/MIME message verification have been rewritten. The verification is much stricter now, and also supports secured headers in the certificate. Verification might now fail while it was successful in v2.15. Also, exception messages might have changed.

## Migration to Version 2.15

- `acme4j-smime` requires BouncyCastle now. The `BouncyCastleProvider` must also be added as security provider.
- In `acme4j-smime`, the `EmailProcessor` constructor is private now. Use `EmailProcessor.plainMessage()` as drop-in replacement.

## Migration to Version 2.13

- The `acme4j-smime` module has switched from _JavaMail_ to _Jakarta Mail_. Unfortunately, this is a breaking API change because classes like `javax.mail.internet.InternetAddress` have moved to respective `jakarta.mail` packages.

  I am aware that this change is going to cause a lot of headache, especially if your project still uses JavaEE instead of JakartaEE. However, JavaEE has been discontinued by Oracle, so all projects are going to have to do this migration sooner or later. Let's just get it over with.

## Migration to Version 2.10

- acme4j now provides real `module-info.java` definitions. It also means that for _building_ this project, Java 9 is the minimum requirement now.

- In a preparation for Java 9 modules, the JSR305 null-safe annotations have been replaced by SpotBugs annotations. This _should_ have no impact on your code, as the method signatures themselves are unchanged. However, the compiler could now complain about some `null` dereferences that have been undetected before. Reason is that JSR305 uses the `javax.annotations` package, which leads to split packages in a Java 9 modular environment.

- When fetching the directory, acme4j now evaluates HTTP caching headers instead of just caching the directory for 1 hour. However, Let's Encrypt explicitly forbids caching, which means that a fresh copy of the directory is now fetched from the server every time it is needed. I don't like it, but it is the RFC conformous behavior. It needs to be [fixed on Let's Encrypt side](https://github.com/letsencrypt/boulder/issues/4814).

- `AcmeProvider.directory(Session, URI)` is now responsible for maintaining the cache. Implementations can use `Session.setDirectoryExpires()`, `Session.setDirectoryLastModified()`, and the respective getters, for keeping track of the local directory state. `AcmeProvider.directory(Session, URI)` may now return `null`, to indicate that the remote directory was unchanged and the local copy is still valid. It's not permitted to return `null` if `Session.hasDirectory()` returns `false`, though! If your `AcmeProvider` is derived from `AbstractAcmeProvider`, and you haven't overridden the `directory()` method, no migration is necessary.

## Migration to Version 2.9

- In the ACME STAR draft 09, the term "recurring" has been changed to "auto-renewal". To reflect this change, all STAR related methods in the acme4j API have been renamed as well. If you are using the STAR extension, you are going to get a number of compile errors, but you will always find a corresponding new method. No functionality has been removed. I decided to do a hard API change because acme4j's STAR support is still experimental.

## Migration to Version 2.8

- Challenges can now be found by their class type instead of a type string, which makes finding a challenge type safe. I recommend to migrate your code to this new way. The classic way is not deprecated and will not be removed though. Example:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);   // old style: by name
Http01Challenge challenge = auth.findChallenge(Http01Challenge.class);  // new style: by type
```

- `Login.bindChallenge()` was documented, but missing. It is available now. If you used a custom solution to bind challenges, you can now use the official way.

## Migration to Version 2.7

- Note that _acme4j_ has an `Automatic-Module-Name` set in the acme-client and acme-utils modules now. If you have added _acme4j_ to your Java 9+ module dependencies, you'll need to fix your dependency declaration to `org.shredzone.acme4j` (acme-client) and `org.shredzone.acme4j.utils` (acme-utils).

- There are no breaking API changes in this version, except of the removal of `CertificateUtils.createTlsAlpn01Certificate(KeyPair, String, byte[])` which has been marked as deprecated in v2.6.

- The ACME draft has been finalized and is now called [RFC 8555](https://tools.ietf.org/html/rfc8555). For this reason, the _acme4j_ API is now stable. There won't be breaking changes to the public API in the future, unless absolutely necessary.

## Migration to Version 2.6

- If you use the `tls-alpn-01` challenge and `CertificateUtils.createTlsAlpn01Certificate()` for generating its test certificate, you need to pass the domain name as an `Identifier` object instead of a `String` now. You can use `Identifier.dns(subject)` for conversion. You can also use `Authorization.getIdentifier()` to get the `Identifier` object immediately.

## Migration to Version 2.5

- The GET compatibility mode has been removed. It also means that the `postasget=false` parameter is ignored from now on. If you need it to connect to your ACME server, do not update to this version until your ACME server has been fixed to support ACME draft 15.

!!! warning
    _acme4j_ before version 2.5 will not work with providers like Let's Encrypt any more!

## Migration to Version 2.4

- There was a major change in ACME draft 15. If you use _acme4j_ in a common way, it will transparently take care of everything in the background, so you won't even notice the change.

  However, if you connect to a different ACME server than Boulder (Let's Encrypt) or Pebble, you may now get strange errors from the server if it does not support the `POST-as-GET` requests of draft 15 yet. In that case, you can add a `postasget=false` parameter to the ACME server URI (e. g. `"https://localhost:15000/dir?postasget=false"`). Note that this is only a temporary workaround. It will be removed in a future version. Ask the server's CA to add support for ACME draft 15.

- The `AcmeProvider.connect()` method now gets the ACME server URI as parameter. It allows to add query parameters to the server URI that change the behavior of the resulting connection. If you have implemented your own AcmeProvider, just change the method's signature to `Connection connect(URI serverUri)`, and ignore the parameter value.

## Migration to Version 2.3

- `Authorization.getDomain()`, `Order.getDomains()` and `Problem.getDomain()` are deprecated now, and will be removed in version 2.4. If you use these methods, use `getIdentifier()` (or `getIdentifiers()`) to get an `Identifier` object, then invoke `Identifier.getDomain()` to get the domain name.

## Migration to Version 2.2

- No migration steps are necessary.

## Migration to Version 2.1

- This version adds [JSR 305](https://jcp.org/en/jsr/detail?id=305) annotations. If you use a null-safe language like Kotlin, or tools like SpotBugs, your code may fail to compile because of detected possible null pointer dereferences and unclosed streams. These are potential bugs that need to be resolved.

- In _acme4j_'s `JSON` class, all `as...()` getters now expect a value to be present. For optional values, use `JSON.Value.optional()` or `JSON.Value.map()`. This class is rarely used outside of _acme4j_ itself, so you usually won't need to change anything.

## Migration to Version 2.0

_acme4j_ 2.0 fully supports the ACMEv2 protocol. Sadly, the ACMEv2 protocol is a major change.

There is no easy recipe to migrate your code to _acme4j_ 2.0. I recommend to have a look at the example, and read this documentation. Altogether, it shouldn't be too much work to update your code, though.
