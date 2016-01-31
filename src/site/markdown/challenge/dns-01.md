# dns-01 Challenge

With the `dns-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content.

After authorizing the challenge, `Dns01Challenge` provides a digest string:

```java
Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
challenge.authorize(registration);

String digest = challenge.getDigest();
```

The CA expects a TXT record at `_acme-challenge.${domain}` with the `digest` string as value.

The challenge is completed when the CA was able to fetch the TXT record and got the correct `digest` returned.
