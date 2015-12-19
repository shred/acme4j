# Let's Encrypt

Web site: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server
* `acme://letsencrypt.org/v01` - Production server, pinned to API v01

## Features

* Connection to the ACME server is pinned to the Let's Encrypt certificate

## Intermediate Certificates

The _Let's Encrypt_ intermediate certificates are available [here](https://letsencrypt.org/certificates/).

## Renewal

Just download the renewed certificate from the certificate URL that was provided by `requestCertificate()`.
