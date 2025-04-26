# dns-01 Challenge

With the `dns-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content.

`Dns01Challenge` provides a resource record name and a digest string:

```java
Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.class);

String resourceName = challenge.getRRName(auth.getIdentifier());
String digest = challenge.getDigest();
```

The CA expects a TXT record at `resourceName` with the `digest` string as value. The `Dns01Challenge.getRRName()` method converts the domain name to a resource record name (including the trailing full stop, e.g. `_acme-challenge.www.example.org.`).

The validation was successful if the CA was able to fetch the TXT record and got the correct `digest` returned.
