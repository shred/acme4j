# ACME Java Client ![build status](http://jenkins.shredzone.net/buildStatus/icon?job=acme4j)

This is a Java client for the [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/draft-ietf-acme-acme-01) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

## Alpha Release!

Please note that even though _acme4j_ is already usable, it is currently in an early alpha state. This means that:

* _acme4j_ is not feature complete yet (see the "Missing" section below).
* The API is not stable. It may change in a manner not compatible to previous versions and without prior notice.
* _acme4j_ could still have major bugs.

As _Let's Encrypt_ is currently in public beta, some of the ACME services may be restricted or not yet available.

The ACME specifications are in draft status and subject to change.

## Features

* Easy to use Java API
* Requires JRE 7 or higher
* Built with maven (package will be made available at Maven Central as soon as beta state is reached)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies
* Extensive unit tests

## Usage

See the [online documentation](http://www.shredzone.org/maven/acme4j/) for how to use _acme4j_. Or just have a look at [the source code of an example](https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java).

## Missing

The following features are planned to be completed for the first beta release, but are still missing:

* Support of account recovery.
* `proofOfPossession-01` and `tls-sni-01` challenge support.

## License

_acme4j_ is open source software. The source code can be found at [GitHub](https://github.com/shred/acme4j) and is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Feel free to send in pull requests!
