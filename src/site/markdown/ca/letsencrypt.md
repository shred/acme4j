# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server
* `acme://letsencrypt.org/v01` - Production server, pinned to API v01

## Features

* Connection to the ACME server is pinned to the Let's Encrypt certificate

## Limits

* Registrations per IP: 10 per 3 hours
* Certificates per Domain: 5 per 7 days
* SANs per Certificate: 100

See [here](https://community.letsencrypt.org/t/public-beta-rate-limits/4772) for the current limits.

## Intermediate Certificates

The _Let's Encrypt_ intermediate certificates are available [here](https://letsencrypt.org/certificates/).

## Renewal

Just download the renewed certificate from the certificate URL that was provided by `requestCertificate()`.
