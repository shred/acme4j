# DNS Challenge

After authorizing the challenge, `DnsChallenge` provides a digest string:

```java
DnsChallenge challenge = auth.findChallenge(DnsChallenge.TYPE);
challenge.authorize(account);

String digest = challenge.getDigest();
```

The CA expects a TXT record at `_acme-challenge.${domain}` with the `digest` string as value.

The challenge is completed when the CA was able to fetch the TXT record and got the correct `digest` returned.
