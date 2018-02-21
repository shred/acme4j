# Challenges

Challenges are used to prove ownership of a domain.

There are different kind of challenges. The most simple is maybe the HTTP challenge, where a file must be made available at the domain that is to be validated. It is assumed that you control the domain if you are able to publish a given file under a given path.

The ACME specifications define these standard challenges:

* [http-01](./http-01.html)
* [dns-01](./dns-01.html)
