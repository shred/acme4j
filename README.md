# ACME Java Client ![build status](https://shredzone.org/badge/acme4j.svg) ![maven central](https://maven-badges.herokuapp.com/maven-central/org.shredzone.acme4j/acme4j/badge.svg)

> **NOTE:** There is currently no _acme4j_ 2.0 release available at Maven Central. To use _acme4j_ with the ACMEv2 protocol, you need to build it yourself and use version `2.0-SNAPSHOT` in your project. Version 2.0 will be available at the latest when _Let's Encrypt_ starts its production ACMEv2 server on February 27th, 2018.
>
> **For production** you should use the latest version available at Maven Central (see the badge above). You can find the corresponding source code in the [acmev1 branch](https://github.com/shred/acme4j/tree/acmev1).

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

## ACME Versions

There are two versions of the ACME protocol specification, ACME v1 and ACME v2.

ACME v1 is currently in production. It is supported by _acme4j_ < 2.0, so **use _acme4j_ < 2.0 for production purposes!**

_Let's Encrypt_ plans to launch an ACME v2 production server on Feburary 27th, 2018. A staging server is already available. _acme4j_ >= 2.0 supports the ACME v2 protocol.

_Let's Encrypt_ has not announced a sunset date for ACME v1 yet, so there is plenty of time for migration.

## Known Issues

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
* Thanks to [Daniel McCarney](https://github.com/cpu) for his help with the ACME protocol, Pebble, and Boulder.
* I also like to thank [everyone who contributed to _acme4j_](https://github.com/shred/acme4j/graphs/contributors).
