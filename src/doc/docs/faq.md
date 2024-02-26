# FAQ and Troubleshooting

## I have lost my account key pair. What can I do?

There is no automatic way to recover the key pair or restore access to your account.

If you just create a new account with a new key pair, subsequent domain authorization attempts are likely to fail because there is already such an authorization associated with your old account.

All you can do is to contact the CA support hotline and ask for support.

You can still revoke certificates without account key pair though, see [here](usage/revocation.md#without-account-key).

## My `Challenge` is in status `PENDING`. What does it mean?

**Symptom:** After the challenge was triggered, it changes to status `PENDING`.

**Cause:** You have triggered the challenge, and are now waiting for the CA to verify it.

**Solution:** Wait until the challenge changes to either `VALID` or `INVALID` state. Do not remove challenge related resources (e.g. HTML files or DNS records) before.


## My `Challenge` returns status `INVALID`. What has gone wrong?

**Symptom:** After the challenge was triggered, it eventually changes to status `INVALID`.

**Cause:** There may be multiple causes for that, but usually it means that the CA could not verify your challenge.

**Solution:** If the status is `INVALID`, invoke `Challenge.getError()` to get the cause of the failure. For example, you can log the output of `challenge.getError().toString()`. Make sure that your challenge is ready for verification _before_ you invoke `Challenge.trigger()`. Also make sure not to remove the challenge until the status is either `VALID` or `INVALID`.

## My `Order` returns status `INVALID`. What has gone wrong?

**Symptom:** Your challenge(s) passed as `VALID`. However when you execute the order, it changes to status `INVALID`. No certificate was issued.

**Cause:** There may be multiple reasons for that. It seems that you are still missing steps that are required by the CA before completion.

**Solution:** If the status is `INVALID`, invoke `Order.getError()` to get the cause of the failure. For example, you can log the output of `order.getError().toString()`.

## My `Order` seems to be stuck in status `PROCESSING`. What can I do?

**Symptom:** Your challenge(s) passed as `VALID`. However when you execute the order, it seems to be stuck in status `PROCESSING`.

**Cause:** The CA may have retained your order to carry out background checks. These checks can take hours or even days. Please read the CA documentation for further details.

**Solution:** There is nothing you can do on software side.

## Browsers do not accept my certificate.

**Symptom:** A certificate was successfully issued. However the browser does not accept the certificate, and shows an error that the cert authority is invalid.

**Cause:** This problem occurs when the staging server of a CA is used (e.g. `acme://letsencrypt.org/staging`). The certificate is signed correctly, but the staging issuer certificate is not known to the browser.

**Solution:** Use the production server of your CA (e.g. `acme://letsencrypt.org`).

## The http-01 challenge fails.

**Symptom:** You set up your response token in the `/.well-known/acme-challenge/` path, and you can also successfully fetch it locally, but the challenge is failing with `Invalid response: 404` (or another HTTP error code).

**Cause:** The CA could not access your response token, but gets a 404 page (or some other kind of error page) instead. Bear in mind that the response token is not evaluated locally by _acme4j_, but is fetched by the CA server.

**Solution:** The CA server could not access your response token from the outside. One reason may be that a firewall or reverse proxy is blocking the access. Another reason may be that your local DNS resolves the domain differently. The CA uses public DNS servers to resolve the domain name. This error often happens when you try to validate a foreign domain (e.g. `example.com` or `example.org`).

## `Account.getOrders()` fails with an exception.

**Symptom:** According to RFC 8555, it should be possible to get a list of all orders of an account. But when I invoke `Account.getOrders()`, an `AcmeProtocolException` is thrown.

**Cause:** _Let's Encrypt_ does not support getting a list of orders, even though it is mandatory by RFC 8555 (see [this issue](https://github.com/letsencrypt/boulder/issues/3335)).

**Solution:** There is no solution. You need to store the location of your orders locally, and use `Login.bindOrder()` to rebind the location to your session and restore the `Order` object.

## The S/MIME certificate challenge fails.

**Sympton:** You try to order an S/MIME certificate from a providing CA. However the CA constantly refuses the response e-mail because the contained ACME response is purportedly invalid.

**Cause:** Unfortunately [RFC 8823](https://tools.ietf.org/html/rfc8823) has an ambiguous specification about how to concatenate the two token parts. The text permits two different interpretations that may give different results. _acme4j_ uses an implementation that corresponds to the [intention of the author of RFC 8823](https://mailarchive.ietf.org/arch/msg/acme/KusfZm3qC50IfcAAuTXtmbFK0KM/). If the CA is implemented following the other interpretation, the ACME e-mail response will not match (see [this issue](https://github.com/shred/acme4j/issues/123)).

**Solution:** It is a difficult situation that is caused by an ambiguous specification, but it is like it is now. Since _acme4j_ follows the intention of the RFC author, I take the position that the _acme4j_ implementation is correct. Please open a bug report at the CA, and refer to [this issue](https://github.com/shred/acme4j/issues/123). If the two tokens are split at a position so the first token won't have trailing base64 padding bits, the CA service can be implemented in a way that is compatible to both interpretations.

## Suddenly acme4j starts throwing `AcmeUserActionRequiredException` everywhere! How can I fix that?

**Sympton:** Many _acme4j_ methods suddenly throw a `AcmeUserActionRequiredException` after interacting with the server. It is impossible to order certificates.

**Cause:** The CA has probably changed its terms of service and wants you to accept them before resuming.

**Solution:** Invoke `AcmeUserActionRequiredException.getInstance()` to get an URL of a web page that describes all further steps to be taken. You might also be able to resolve the issue by logging into your CA's account, but that is up to the CA's discretion.

Unfortunately, manual action is required in any case, there is no way to automate this process. This is an intentional protocol decision, and _acme4j_ is just the messenger.

## Where can I find more help?

* [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
* [Let's Encrypt Community](https://community.letsencrypt.org/) - If the question is _acme4j_ related, please mention it in your post.
* [SSL.com Knowledgebase](https://www.ssl.com/info/)
