# dns-account-01 Challenge

With the `dns-account-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content.

This challenge is specified in [draft-ietf-acme-dns-account-label-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-account-label/).

!!! warning
    The support of this challenge is **experimental**. The implementation is only unit tested for compliance with the specification, but is not integration tested yet. There may be breaking changes in this part of the API in future releases.

With the `dns-account-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content.

`DnsAccount01Challenge` provides a digest string and a resource record name:

```java
DnsAccount01Challenge challenge = auth.findChallenge(DnsAccount01Challenge.class);

String resourceRecordName = challenge.getRRName(auth.getIdentifier());
String digest = challenge.getDigest();
```

The CA expects a TXT record at `resourceRecordName` with the `digest` string as value. The `getRRName()` method converts the domain name to a resource record name (including the trailing full stop).

The validation was successful if the CA was able to fetch the TXT record and got the correct `digest` returned.
