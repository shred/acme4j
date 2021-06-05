# FAQ and Troubleshooting

## Browsers do not accept my certificate.

**Symptom:** A certificate was successfully issued. However the browser does not accept the certificate, and shows an error that the cert authority is invalid.

**Cause:** This problem occurs when the staging server of a CA is used (e.g. `acme://letsencrypt.org/staging`). The certificate is signed correctly, but the staging issuer certificate is not known to the browser.

**Solution:** Use the production server of your CA (e.g. `acme://letsencrypt.org`).

## The http-01 challenge fails.

**Symptom:** You set up your response token in the `/.well-known/acme-challenge/` path, and you can also successfully fetch it locally, but the challenge is failing. In the error details you find a strange HTML fragment.

**Cause:** The CA could not access your response token, but gets a 404 page (or some other kind of error page) instead. The HTML fragment in the error details is actually a part of that error page. Bear in mind that the response token is not evaluated locally by _acme4j_, but is fetched by the CA server.

**Solution:** The CA server could not access your response token from the outside. One reason may be that a firewall or reverse proxy is blocking the access. Another reason may be that your local DNS resolves the domain differently. The CA uses public DNS servers to resolve the domain name. This error often happens when you try to validate a foreign domain (e.g. `example.com` or `example.org`).

## `Account.getOrders()` fails with an exception.

**Symptom:** According to RFC 8555, it should be possible to get a list of all orders of an account. But when I invoke `Account.getOrders()`, an `AcmeProtocolException` is thrown.

**Cause:** _Let's Encrypt_ does not support getting a list of orders, even though it is mandatory by RFC 8555 (see [this issue](https://github.com/letsencrypt/boulder/issues/3335)).

**Solution:** There is no solution. You need to store the location of your orders locally, and use `Login.bindOrder()` to rebind the location to your session and restore the `Order` object.