# dns-persist-01 Challenge

With the `dns-persist-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record that refers to your account.

In contrast to the [`dns-01`](dns-01.md) challenge, the DNS TXT records are long-term and can be created manually, so your services do not need the access credentials of your DNS server.

This challenge is specified in [draft-ietf-acme-dns-persist-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/).

!!! warning
    The support of this challenge is **experimental**. The implementation is only unit tested for compliance with the specification, but is not integration tested yet. There may be breaking changes in this part of the API in future releases. Semantic versioning does not apply here.

`DnsPersist01Challenge` provides a resource record name and a digest string:

```java
DnsPersist01Challenge challenge = auth.findChallenge(DnsPersist01Challenge.class);

String resourceName = challenge.getRRName(auth.getIdentifier());
String rdata = challenge.getRData();
```

The CA expects a TXT record at `resourceName` with the `rdata` string as value. The `DnsPersist01Challenge.getRRName()` method converts the domain name to a resource record name (including the trailing full stop, e.g. `_validation-persist.www.example.org.`).

The `rdata` value is bound to your account at the CA. It stays the same for future challenges. If the TXT record is already set, you can skip ahead and trigger the challenge. However, most CAs will automatically authorize your domain if the TXT record exists, so you may not even need to complete the challenge.

The validation was successful if the CA was able to fetch the TXT record.

## Additional parameters

To add further parameters to the RDATA, a builder can be used:

```java
String rdata = challenge.buildRData()
        .issuerDomainName("ca.example.com")
        .wildcard()
        .persistUntil(Instant.now().plus(3, ChronoUnit.MONTHS))
        .noQuotes()
        .build();
```

* `issuerDomainName` sets a different issuer domain name. It must be one of `DnsPersist01Challenge.getIssuerDomainNames()`. If not set, the first issuer domain name of that list is taken as default.
* `wildcard` marks that you want to authorize wildcard.
* `persistUntil` limits the validity of the TXT record. If not set, the TXT record will be valid indefinitely.
* `noQuotes` generates RDATA without quote-enclosed strings. You _must_ then take care of long RDATA values yourself!

`getRdata()` is just a shortcut for `buildRData().build()`.
