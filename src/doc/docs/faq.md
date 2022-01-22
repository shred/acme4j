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

## The S/MIME certificate challenge fails.

**Sympton:** You try to order an S/MIME certificate from a providing CA. However the CA constantly refuses the response e-mail because the contained ACME response is purportedly invalid.

**Cause:** Unfortunately [RFC 8823](https://tools.ietf.org/html/rfc8823) has an ambiguous specification about how to concatenate the two token parts. The text permits two different interpretations that may give different results. _acme4j_ uses an implementation that corresponds to the [intention of the author of RFC 8823](https://mailarchive.ietf.org/arch/msg/acme/KusfZm3qC50IfcAAuTXtmbFK0KM/). If the CA is implemented following the other interpretation, the ACME e-mail response will not match (see [this issue](https://github.com/shred/acme4j/issues/123)).

**Solution:** It is a difficult situation that is caused by an ambiguous specification, but it is like it is now. Since _acme4j_ follows the intention of the RFC author, I take the position that the _acme4j_ implementation is correct. Please open a bug report at the CA, and refer to [this issue](https://github.com/shred/acme4j/issues/123). If the two tokens are split at a position so the first token won't have trailing base64 padding bits, the CA service can be implemented in a way that is compatible to both interpretations.
