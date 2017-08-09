# ACME Java Client ![build status](https://shredzone.org/badge/acme4j.svg) ![maven central](https://maven-badges.herokuapp.com/maven-central/org.shredzone.acme4j/acme4j/badge.svg)

This is a Java client for the [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/draft-ietf-acme-acme-06) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_.

## Features

* Supports the "ACME v1" protocol that is used by _Let's Encrypt_
* Easy to use Java API
* Requires JRE 8 or higher
* Built with maven, packages available at [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22org.shredzone.acme4j%22)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies
* Extensive unit tests

## Usage

* See the [online documentation](https://shredzone.org/maven/acme4j/) about how to use _acme4j_.
* For a quick start, have a look at [the source code of an example](https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java).

## Compatibility

This version of _acme4j_ is tailor-made for _Let's Encrypt_ and other CAs that use the [Boulder](https://github.com/letsencrypt/boulder) server and the "ACME v1" protocol.

Support for the latest [ACME v2](https://letsencrypt.org/2017/06/14/acme-v2-api.html) protocol is currently being implemented in the ["draft" branch](https://github.com/shred/acme4j/tree/draft) of _acme4j_. _Let's Encrypt_ will offer an ACME v2 API endpoint by January 2018.

## Contribute

* Fork the [Source code at GitHub](https://github.com/shred/acme4j). Feel free to send pull requests.
* Found a bug? [File a bug report!](https://github.com/shred/acme4j/issues)

## License

_acme4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements

* I would like to thank Brian Campbell and all the other [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) developers. _acme4j_ would not exist without your excellent work.
* I also like to thank everyone who contributed to _acme4j_.
