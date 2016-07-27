# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server
* `acme://letsencrypt.org/v01` - Production server, pinned to API v01

## Features

* Accepts the ACME server certificate of Let's Encrypt even on older Java versions

## Note

* _Let's Encrypt_ diverges from the ACME specifications for various reasons. For this reason, some parts of the _acme4j_ API may not behave as documented. [See here for more details.](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)

## Limits

* Registrations per IP: 10 per 3 hours
* Certificates per Domain: 5 per 7 days
* SANs per Certificate: 100

See [here](https://community.letsencrypt.org/t/public-beta-rate-limits/4772) for the current limits.
