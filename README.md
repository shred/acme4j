# ACME Java Client ![build status](https://jenkins.shredzone.net/project/acme4j/builds/status.png?ref=master)

This is a Java client for the [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/draft-ietf-acme-acme-01) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

## Migration Guide

Major parts of the _acme4j_ API have changed in this version.

Please see the [migration guide](https://shredzone.org/maven/acme4j/migration.html) for how to update your code to the new API. It should just be a matter of a few minutes.

## Features

* Supports ACME protocol up to [draft 02](https://tools.ietf.org/html/draft-ietf-acme-acme-02), with a few parts of [draft 03](https://tools.ietf.org/html/draft-ietf-acme-acme-03)
* Easy to use Java API
* Requires JRE 7 or higher
* Built with maven, packages available at [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22org.shredzone.acme4j%22)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies
* Extensive unit tests

## Usage

* See the [online documentation](https://shredzone.org/maven/acme4j/) about how to use _acme4j_.
* For a quick start, have a look at [the source code of an example](https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java).

## Compatibility

_acme4j_ supports all CAs that implement the ACME protocol up to [draft 02](https://tools.ietf.org/html/draft-ietf-acme-acme-02). The latest [draft 03](https://tools.ietf.org/html/draft-ietf-acme-acme-03) is partially supported. There is currently no public server available that implements all of draft 03.

The most prominent ACME CA, _Let's Encrypt_, [diverges from the specifications](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md). Some of the _acme4j_ features may not work with _Let's Encrypt_. Also, the usage of deprecated API parts may be required.

The _acme4j_ API may change as features are added to, and other features removed from the [ACME specifications](https://github.com/ietf-wg-acme/acme), because they are still work in progress. Also see the [_acme4j_ bug tracker](https://github.com/shred/acme4j/issues) for missing and untested features.

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests.
* Found a bug? [File a bug report!](https://github.com/shred/acme4j/issues)

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements

* I would like to thank Brian Campbell and all the other [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) developers. _acme4j_ would not exist without your excellent work.
