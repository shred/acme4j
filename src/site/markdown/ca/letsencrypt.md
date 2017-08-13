# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server

## Features

* Accepts the ACME server certificate of Let's Encrypt even on older Java versions

## Limits

* Registrations per IP: 10 per 3 hours
* Certificates per Domain: 5 per 7 days
* SANs per Certificate: 100

See [here](https://community.letsencrypt.org/t/public-beta-rate-limits/4772) for the current limits.
