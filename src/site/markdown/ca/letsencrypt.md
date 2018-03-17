# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server
* `acme://letsencrypt.org/v01` - Production server, pinned to API v01

## Compatibility

Java 8u101 or later is required for connecting to the _Let's Encrypt_ servers.

## Limits

* Registrations per IP: 10 per 3 hours
* Certificates per Domain: 5 per 7 days
* SANs per Certificate: 100

See [here](https://community.letsencrypt.org/t/public-beta-rate-limits/4772) for the current limits.
