# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server
* `acme://letsencrypt.org/v01` - Production server, pinned to API v01

## Compatibility

If you have to use a Java version that is older than 8u101 and does not accept the _IdenTrust_ certificates of the _Let's Encrypt_ servers, you can use a hardcoded local truststore as a workaround by setting the `acme4j.le.certfix` system property to `true`. Please note that the hardwired certificate will expire by June, 2018.

## Limits

* Registrations per IP: 10 per 3 hours
* Certificates per Domain: 5 per 7 days
* SANs per Certificate: 100

See [here](https://community.letsencrypt.org/t/public-beta-rate-limits/4772) for the current limits.
