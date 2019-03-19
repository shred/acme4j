# ACME Java Client ![build status](https://shredzone.org/badge/acmev1/acme4j.svg)

This is a Java client for the [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/draft-ietf-acme-acme-06) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

## ACME v1

This _acme4j_ branch implements the deprecated _ACME v1_ protocol. _Let's Encrypt_ has announced an [End of Life Plan for ACME v1](https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430). According to this plan, access to the ACME v1 servers will be limited starting November 2019, and completely stopped in June 2021.

**Please [migrate](https://shredzone.org/maven/acme4j/migration.html) your code to _acme4j_ v2.5 or higher soon!**

This _acme4j_ v1 branch will **only receive security fixes until November 1st, 2019**. After that date, ACME v1 support will end and this branch will be closed.

## Features

* Supports the "ACME v1" protocol that is used by _Let's Encrypt_
* Easy to use Java API
* Requires JRE 8u101 or higher
* Built with maven, packages available at [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22org.shredzone.acme4j%22)
* Small: `acme4j-client` only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies
* Only the optional `acme4j-utils` module requires [Bouncy Castle](http://www.bouncycastle.org)
* Extensive unit tests

## Usage

* See the [online documentation](https://shredzone.org/maven/acme4j-acmev1/) about how to use _acme4j_.
* For a quick start, have a look at [the source code of an example](https://github.com/shred/acme4j/blob/acmev1/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java).

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests. However, work on this branch is discontinued in favor of the ACMEv2 implementation in the master branch. We will only accept bug fixes and security related patches.
* Found a bug? [File a bug report](https://github.com/shred/acme4j/issues). Please add a note that you are referring to the old ACMEv1 implementation!

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements

* I would like to thank Brian Campbell and all the other [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) developers. _acme4j_ would not exist without your excellent work.
* I also like to thank everyone who contributed to _acme4j_.
