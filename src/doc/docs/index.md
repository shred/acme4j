# acme4j

A Java client for the _Automatic Certificate Management Environment_ (ACME) protocol as specified in [RFC 8555](https://tools.ietf.org/html/rfc8555).

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

The source code can be found at [GitHub](https://github.com/shred/acme4j) and is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Latest version: ![maven central](https://shredzone.org/maven-central/org.shredzone.acme4j/acme4j/badge.svg)

## Features

* Mature and stable code base. First release was in December 2015!
* Fully [RFC 8555](https://tools.ietf.org/html/rfc8555) compliant
* Supports the `http-01`, `dns-01`, and `tls-alpn-01` ([RFC 8737](https://tools.ietf.org/html/rfc8737)) challenges
* Supports [RFC 8738](https://tools.ietf.org/html/rfc8738) IP identifier validation
* Supports [RFC 8739](https://tools.ietf.org/html/rfc8739) short-term automatic certificate renewal (experimental)
* Supports [RFC 8823](https://tools.ietf.org/html/rfc8823) for S/MIME certificates (experimental)
* Easy to use Java API
* Requires JRE 8 (update 101) or higher. For building the project, Java 9 or higher is required.
* Built with maven, packages available at [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22org.shredzone.acme4j%22)
* Extensive unit and integration tests
* Reported to work on Android. However, this platform is not officially supported.
* Adheres to [Semantic Versioning](https://semver.org/)

## Dependencies

* [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home)
* [slf4j](http://www.slf4j.org/)
* For `acme4j-utils`: [Bouncy Castle](https://www.bouncycastle.org/)
* For `acme4j-smime`: [Jakarta Mail](https://eclipse-ee4j.github.io/mail/), [Bouncy Castle](https://www.bouncycastle.org/)

## Quick Start

There is an [example source code](example.md) included in this project. It gives an example of how to get a TLS certificate with _acme4j_.

## Modules

_acme4j_ consists of five modules. All modules are [available at Maven Central](https://mvnrepository.com/artifact/org.shredzone.acme4j) and can easily be added to the dependency list of your project. You can also download the jar files [at GitHub](https://github.com/shred/acme4j/releases/latest).

acme4j-client
:   [`acme4j-client`](https://mvnrepository.com/artifact/org.shredzone.acme4j/acme4j-client/latest) is the main module. It contains everything that is required to get certificates for domains. It only requires [jose4j](https://bitbucket.org/b_c/jose4j) and [slf4j](https://www.slf4j.org/).

    The Java module name is `org.shredzone.acme4j`.

acme4j-utils
:   [`acme4j-utils`](https://mvnrepository.com/artifact/org.shredzone.acme4j/acme4j-utils/latest) contains utility classes for creating key pairs, CSRs, and certificates. It requires [Bouncy Castle](https://www.bouncycastle.org/java.html) though.

    The Java module name is `org.shredzone.acme4j.utils`.

acme4j-smime
:   [`acme4j-smime`](https://mvnrepository.com/artifact/org.shredzone.acme4j/acme4j-smime/latest) contains the [RFC 8823](https://tools.ietf.org/html/rfc8823) implementation for ordering S/MIME certificates. It requires [Bouncy Castle](https://www.bouncycastle.org/java.html) and a `javax.mail` implementation.

    The Java module name is `org.shredzone.acme4j.smime`.

acme4j-example
:   This module only contains [an example code](example.md) that demonstrates how to get a certificate with _acme4j_. It depends on `acme4j-client` and `acme4j-utils`. It is not useful as a dependency in other projects.

acme4j-it
:   [`acme4j-it`](https://mvnrepository.com/artifact/org.shredzone.acme4j/acme4j-it/latest) mainly serves as integration test suite for _acme4j_ itself. It is not really useful as a dependency in other projects. However if you write own integration tests using [pebble](https://github.com/letsencrypt/pebble) and [pebble-challtestsrv](https://hub.docker.com/r/letsencrypt/pebble-challtestsrv), you may find the [`challtestsrv` configuration client](acme4j-it/apidocs/org.shredzone.acme4j.it/org/shredzone/acme4j/it/BammBammClient.html) useful in your project.

    The Java module name is `org.shredzone.acme4j.it`.

## Announcements

Follow our Mastodon feed for release notes and other acme4j related news.

* Mastodon: <a href="https://foojay.social/@acme4j" rel="me">@acme4j@foojay.social</a>
* RSS: https://foojay.social/@acme4j.rss

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests.
* Found a bug? [File a bug report!](https://github.com/shred/acme4j/issues)

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
