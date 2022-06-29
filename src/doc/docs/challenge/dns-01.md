# dns-01 Challenge

With the `dns-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content.

`Dns01Challenge` provides a digest string:

```java
Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.class);
String domain = auth.getIdentifier().getDomain();

String resourceName = Dns01Challenge.toRRName(auth.getIdentifier());
String digest = challenge.getDigest();
```

The CA expects a TXT record at `_acme-challenge.${domain}.` with the `digest` string as value. The `Dns01Challenge.toRRName()` method converts the domain name to a resource record name (including the trailing full stop, e.g. `_acme-challenge.www.example.org.`). The `_acme-challenge` prefix is also available as constant (`Dns01Challenge.RECORD_NAME_PREFIX`).

The validation was successful if the CA was able to fetch the TXT record and got the correct `digest` returned.
