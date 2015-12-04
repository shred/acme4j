# ACME Java Client ![build status](http://jenkins.shredzone.net/buildStatus/icon?job=acme4j)

*SOURCE IS COMING SOON!*

This is a Java client for the [ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-01) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_. The source code can be found at [GitHub](https://github.com/shred/acme4j) and is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Features
--------

* Easy to use Java API
* Requires JRE 7 or higher
* Built with maven (package will be available shortly at Maven Central)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies. [Bouncy Castle](https://www.bouncycastle.org/java.html) is recommended for some features, but is not required.
