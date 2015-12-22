# ACME Java Client ![build status](https://jenkins.shredzone.net/project/acme4j/builds/status.png?ref=master)

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

The following feature is planned to be completed for the first beta release, but is still missing:

* `proofOfPossession-01` challenge support.

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests.
* Found a bug? [File a bug report!](https://github.com/shred/acme4j/issues)

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements

* I would like to thank Brian Campbell and all the other [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) developers. _acme4j_ would not exist without your excellent work.
