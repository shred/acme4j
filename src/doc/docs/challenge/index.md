# Challenges

Challenges are used to prove ownership of a domain.

There are different kinds of challenges. The most simple is maybe the HTTP challenge, where a file must be made available at the domain that is to be validated. It is assumed that you control the domain if you are able to publish a given file under a given path.

The ACME specifications define these standard challenges:

* [dns-01](dns-01.md) ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4), section 8.4)
* [http-01](http-01.md) ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3), section 8.3)

_acme4j_ also supports these non-standard challenges:

* [dns-account-01](dns-account-01.md) ([draft-ietf-acme-dns-account-label-02](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-account-label/))
* [dns-persist-01](dns-persist-01.md) ([draft-ietf-acme-dns-persist-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/))
* [email-reply-00](email-reply-00.md) ([RFC 8823](https://tools.ietf.org/html/rfc8823))
* [tls-alpn-01](tls-alpn-01.md) ([RFC 8737](https://tools.ietf.org/html/rfc8737))
