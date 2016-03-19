# Challenges

Challenges are used to prove ownership of a domain.

There are different kind of challenges. The most simple is maybe the HTTP challenge, where a file must be made available at the domain that is to be validated. It is assumed that you control the domain if you are able to publish a given file under a given path.

The CA offers one or more sets of challenges. At least one set has to be completed in order to prove ownership.

The ACME specifications define these standard challenges:

* [http-01](./http-01.html)
* [dns-01](./dns-01.html)
* [tls-sni-01](./tls-sni-01.html)
* [tls-sni-02](./tls-sni-02.html)
* [proof-of-possession-01](./proof-of-possession-01.html)
