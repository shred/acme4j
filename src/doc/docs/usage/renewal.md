# Certificate Renewal

Certificates are only valid for a limited time, and need to be renewed before expiry.

To read the expiration date of your certificate, use `X509Certificate.getNotAfter()`. The certificate is eligible to be renewed a few days or weeks before its expiry. Check the documentation of your CA about a recommended time window. Also do not postpone the renewal to the last minute, as there can always be unexpected network issues that delay the issuance of a renewed certificate.

!!! tip
    Some CAs send a notification mail to your account's mail addresses in time before expiration. However you should not rely on those mails, and only use them as an ultimate warning.

## How to Renew

There is no special path for renewing a certificate. To renew it, just [order](order.md) the certificate again.

## Renewal Information

_acme4j_ supports the [draft-ietf-acme-ari-06](https://www.ietf.org/archive/id/draft-ietf-acme-ari-06.html) draft.

You can check if the CA offers renewal information by invoking `Certificate.hasRenewalInfo()`. If it does, you can get a suggested time window for certificate nenewal by invoking `Certificate.getRenewalInfo()`.

When renewing a certificate, you can use `OrderBuilder.replaces()` to mark your current certificate as the one being replaced. This step is optional though.

!!! note
    Starting with _acme4j_ v3.2.0, the now obsolete [draft-ietf-acme-ari-01](https://www.ietf.org/archive/id/draft-ietf-acme-ari-01.html) is not supported anymore! If your server requires the old draft, use _acme4j_ v3.1.1 until the CA upgraded its systems. Because of the dynamic nature of the draft, all parts of the API that are related to this draft may be changed or removed without notice. SemVer rules do not apply here.

## Short-Term Automatic Renewal

_acme4j_ supports [RFC 8739](https://tools.ietf.org/html/rfc8739) for Short-Term Automatic Renewal (STAR) of certificates.

To find out if the CA supports the STAR extension, check the metadata:

```java
if (session.getMetadata().isAutoRenewalEnabled()) {
  // CA supports STAR!
}
```

If STAR is supported, you can enable automatic renewals by adding `autoRenewal()` to the order parameters:

```java
Order order = account.newOrder()
        .domain("example.org")
        .autoRenewal()
        .create();
```

You can also use `autoRenewalStart()`, `autoRenewalEnd()`, `autoRenewalLifetime()` and `autoRenewalLifetimeAdjust()` to change the time span and frequency of automatic renewals. You cannot use `notBefore()` and `notAfter()` in combination with `autoRenewal()` though.

The `Metadata` object also holds the accepted renewal limits (see `Metadata.getAutoRenewalMinLifetime()` and `Metadata.getAutoRenewalMaxDuration()`).

The STAR certificates are automatically renewed by the CA. You will always find the latest certificate at the certificate location URL.

To download the latest certificate issue, you can bind the certificate URL to your `Login` and then use the `Certificate` object.

```java
URL certificateUrl = ... // URL of the certificate

Certificate cert = login.bindCertificate(certificateUrl);
X509Certificate latestCertificate = cert.getCertificate();
```

!!! note
    STAR based certificates cannot be revoked. However, as it is the nature of these certs to be very short-lived, this does not pose an actual security issue.

### Fetching STAR certificates via GET

Usually the STAR certificate must be fetched from the location URL by an authorized `POST-as-GET` request. If supported by the CA, it is possible to change the method to a plain `GET` request, so the certificate can be fetched by a simple HTTP client (like curl) without authentication.

To enable this `GET` method, first check if it is offered by the CA, by invoking `Metadata.isAutoRenewalGetAllowed()`. If it is true, add `autoRenewalEnableGet()` to the order options. After the order was finalized, the certificate will be available via both `GET` and `POST-as-GET` methods.

### Cancelling Auto-Renewals

Use `Order.cancelAutoRenewal()` to terminate automatical certificate renewals.
