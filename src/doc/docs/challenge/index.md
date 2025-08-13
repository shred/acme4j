# Challenges

Challenges are used to prove ownership of a domain.

There are different kinds of challenges. The most simple is maybe the HTTP challenge, where a file must be made available at the domain that is to be validated. It is assumed that you control the domain if you are able to publish a given file under a given path.

The ACME specifications define these standard challenges:

* [dns-01](dns-01.md)
* [http-01](http-01.md)

_acme4j_ also supports these non-standard challenges:

* [dns-account-01](dns-account-01.md) ([draft-ietf-acme-dns-account-label-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-account-label/))
* [email-reply-00](email-reply-00.md)
* [tls-alpn-01](tls-alpn-01.md)
