# ACME Java Client ![build status](http://jenkins.shredzone.net/buildStatus/icon?job=acme4j)

This is a Java client for the [ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-01) protocol.

ACME is a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.

This Java client helps connecting to an ACME server, and performing all necessary steps to manage certificates.

It is an independent open source implementation that is not affiliated with or endorsed by _Let's Encrypt_. The source code can be found at [GitHub](https://github.com/shred/acme4j) and is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Alpha Release!
--------------

Please note that even though _acme4j_ is already usable, it is currently in an early alpha state. This means that:

* _acme4j_ is not feature complete yet (see the "Missing" section below).
* The API is not stable. It may change in a manner not compatible to previous versions and without prior notice.
* _acme4j_ is not thoroughly tested yet, and may still have major bugs.

Features
--------

* Easy to use Java API
* Requires JRE 7 or higher
* Built with maven (package will be made available at Maven Central as soon as beta state is reached)
* Small, only requires [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) and [slf4j](http://www.slf4j.org/) as dependencies. [Bouncy Castle](https://www.bouncycastle.org/java.html) is recommended, but not required.

How to Use
----------

_acme4j_ consists of a few modules:

* _acme4j-client_: This is the main module. It contains the ACME client and everything needed for communication with an ACME server.
* _acme4j-letsencrypt_: A _Let's Encrypt_ service. Just add it as dependency, it will neatly plug into the client.
* _acme4j-utils_: Some utility classes that may be helpful for creating key pairs, certificates, and certificate signing requests. Requires [Bouncy Castle](https://www.bouncycastle.org/java.html).
* _acme4j-example_: An example tool that performs all steps for registering a new account at _Let's Encrypt_ and getting a certificate for a set of domain names. This is a good starting point to find out how _acme4j_ is used.

Missing
-------

The following features are planned to be completed for the first beta release, but are still missing:

* Support of account recovery and certificate revocation.
* `proofOfPossession-01` and `tls-sni-01` challenge support.
* Extensive unit tests.
* Better error handling.
* Some hardening (like plausibility checks).
* Full documentation.

_acme4j_ is open source software. Feel free to send in pull requests!
