# ACME Java Client ![build status](https://shredzone.org/badge/acme4j.svg) ![maven central](https://maven-badges.herokuapp.com/maven-central/org.shredzone.acme4j/acme4j/badge.svg)

This is a Java client for the [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/draft-ietf-acme-acme-09) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

## Features

* Fully supports the ACME v2 protocol up to [draft 09](https://tools.ietf.org/html/draft-ietf-acme-acme-09)
* Easy to use Java API
* Requires JRE 8 (update 101) or higher
* Built with maven, packages available at [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22org.shredzone.acme4j%22)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies
* Extensive unit and integration tests

## Work in Progress!

There are two versions of the ACME specification, ACME v1 and ACME v2.

ACME v1 is currently in production. It is supported by _acme4j_ < 2.0, so **use _acme4j_ < 2.0 for production purposes!**

At the moment, _Let's Encrypt_ only provides an ACME v2 staging server for testing purposes. An ACME v2 production server is planned to be launched on Feburary 27th, 2018. _acme4j_ >= 2.0 supports the ACME v2 protocol.

_Let's Encrypt_ has not announced a sunset date for ACME v1 yet, so there is plenty of time for migration. _acme4j_ < 2.0 will be maintained in the [acmev1 branch](https://github.com/shred/acme4j/tree/acmev1) until sunset of the ACME v1 protocol.

## Known Issues

* _Let's Encrypt_ does not support the `tls-sni-02` challenge yet, while _acme4j_ does not provide `tls-sni-01` support any more. If you use tls-sni, do not upgrade to _acme4j_ v2 yet!
* The _acme4j_ v2 API is still subject to change.
* Integration tests do not fully cover all functions. The standard methods for creating an account, ordering, and downloading a certificate are tested. Other methods are not tested yet, and may not work as expected.

## Usage

* See the [online documentation](https://shredzone.org/maven/acme4j/) about how to use _acme4j_.
* For a quick start, have a look at [the source code of an example](https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java).

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests.
* Found a bug? [File a bug report!](https://github.com/shred/acme4j/issues)

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements

* I would like to thank Brian Campbell and all the other [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) developers. _acme4j_ would not exist without your excellent work.
* I also like to thank everyone who contributed to _acme4j_.
