# Order a Certificate

Once you have your account set up, you are ready to order certificates.

Use your `Account` object to order the certificate, by using the `newOrder()` method. It returns an `OrderBuilder` object that helps you to collect the parameters of the order. You can give one or more domain names. Optionally you can also give your desired `notBefore` and `notAfter` dates for the generated certificate, but it is at the discretion of the CA to use (or ignore) these values.

```java
Account account = ... // your Account object

Order order = account.newOrder()
        .domains("example.org", "www.example.org", "m.example.org")
        .notAfter(Instant.now().plus(Duration.ofDays(20L)))
        .create();
```

<div class="alert alert-info" role="alert">
The number of domains per certificate may be limited. See your CA's documentation for the limits.
</div>

The `Order` resource contains a collection of `Authorization`s that can be read from the `getAuthorizations()` method. You must process _all of them_ in order to get the certificate, except those with a `VALID` status.

```java
for (Authorization auth : order.getAuthorizations()) {
  if (auth.getStatus() != Status.VALID) {
    processAuth(auth);
  }
}
```

## Process an Authorization

The `Authorization` instance contains further details about how you can prove ownership of your domain. An ACME server offers combinations of different authorization methods, called `Challenge`s.

`getChallenges()` returns a collection of all `Challenge`s offered by the CA for domain ownership validation. You only need to complete _one_ of them to successfully authorize your domain.

The simplest way is to invoke `findChallenge()`, stating the challenge type your system is able to provide:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
```

It returns a properly casted `Challenge` object, or `null` if your challenge type was not acceptable. In this example, your system is able to respond to a [http-01](../challenge/http-01.html) challenge.

The returned `Challenge` resource provides all the data that is necessary for a successful verification of your domain ownership. Your response depends on the challenge type (see the [documentation of challenges](../challenge/index.html)).

After you have performed the necessary steps to set up the response to the challenge (e.g. configuring your web server or modifying your DNS records), the ACME server is told to test your response:

```java
challenge.trigger();
```

Now you have to wait for the server to test your response and set the authorization status to `VALID` or `INVALID`. The easiest (but admittedly also the ugliest) way is to poll the status:

```java
while (auth.getStatus() != Status.VALID) {
  Thread.sleep(3000L);
  auth.update();
}
```

This is a very simple example. You should limit the number of loop iterations, and also handle the case that the status could turn to `INVALID`. If you know when the CA server actually requested your response (e.g. when you notice a HTTP request on the response file), you should start polling after that event.

The CA server may start the validation immediately after `trigger()` is invoked, so make sure your server is ready to respond to requests before invoking `trigger()`. Otherwise the challenge might fail immediately.

`update()` may throw an `AcmeRetryAfterException`, giving an estimated instant in `getRetryAfter()` when the authorization is completed. You should then wait until that moment has been reached, before trying again. The state of the `Authorization` instance is still updated when this exception is thrown.

When the authorization status is `VALID`, you have successfully authorized your domain.

The response you have set up before is not needed any more. You can (and should) remove it now.

## Finalize the Order

After successfully completing all authorizations, the order needs to be finalized by providing PKCS#10 CSR file. A single domain may be set as _Common Name_. Multiple domains must be provided as _Subject Alternative Name_. You must provide exactly the domains that you had passed to the `order()` method above, otherwise the finalization will fail. It depends on the CA if other CSR properties (_Organization_, _Organization Unit_ etc.) are accepted. Some may require these properties to be set, while others may ignore them when generating the certificate.

CSR files can be generated with command line tools like `openssl`. Unfortunately the standard Java does not offer classes for that, so you'd have to resort to [Bouncy Castle](http://www.bouncycastle.org/java.html) if you want to create a CSR programmatically. In the `acme4j-utils` module, there is a [`CSRBuilder`](../apidocs/org/shredzone/acme4j/util/CSRBuilder.html) for your convenience. You can also use [`KeyPairUtils`](../apidocs/org/shredzone/acme4j/util/KeyPairUtils.html) for generating a new key pair for your domain.

<div class="alert alert-info" role="alert">
Do not just use your account key pair as domain key pair, but always generate separate key pairs!
</div>

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");
csrb.addDomain("www.example.org");
csrb.addDomain("m.example.org");
csrb.setOrganization("The Example Organization")
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

It is a good idea to store the generated CSR somewhere, as you will need it again for renewal:

```java
csrb.write(new FileWriter("example.csr"));
```

After that, finalize the order:

```java
order.execute(csr);
```

## Wildcard Certificates

You can also generate a wildcard certificate that is valid for all subdomains of a domain, by prefixing the domain name with `*.` (e.g. `*.example.org`). The domain itself is not covered by the wildcard certificate, and also needs to be added to the order if necessary.

<div class="alert alert-info" role="alert">

_acme4j_ accepts all kind of wildcard notations (e.g. `www.*.example.org`, `*.*.example.org`). However, those notations are not specified and may be rejected by your CA.
</div>

You must be able to prove ownership of the domain that you want to order a wildcard certificate for. The corresponding `Authorization` resource only refers to that domain, and does not contain the wildcard notation.

The following example creates an `Order` and a CSR for `example.org` and `*.example.org`:

```java
Order order = account.newOrder()
        .domains("example.org", "*.example.org")
        .create();

KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");    // example.org itself, if necessary
csrb.addDomain("*.example.org");  // wildcard for all subdomains
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();

order.execute(csr);
```

In the subsequent authorization process, you would have to prove ownership of the `example.org` domain.

<div class="alert alert-info" role="alert">

Some CAs may reject wildcard certificate orders, may only offer a limited set of `Challenge`s, or may involve `Challenge`s that are not documented here. Refer to your CA's documentation to find out about the wildcard certificate policy.
</div>

## Pre-Authorize a Domain

It is possible to pro-actively authorize a domain. This can be useful to find out what challenges are requested by the CA to authorize a domain, before actually ordering a certificate. It may also help to speed up the ordering process, as already completed authorizations do not need to be completed again when ordering the certificate.

```java
Account account = ... // your Account object
String domain = ...   // Domain name to authorize

Authorization auth = account.preAuthorizeDomain(domain);
```

<div class="alert alert-info" role="alert">

Some CAs may not offer domain pre-authorization. `preAuthorizeDomain()` will then fail and throw an `AcmeException`.
</div>

<div class="alert alert-info" role="alert">

Some CAs may not offer wildcard domain pre-authorization, but only wildcard domain orders.
</div>

## Deactivate an Authorization

It is possible to deactivate an `Authorization`, for example if you sell the associated domain.

```java
auth.deactivate();
```

<div class="alert alert-info" role="alert">
It is not documented if the deactivation of an authorization also revokes the related certificate. If the certificate should be revoked, revoke it manually before deactivation.
</div>

## Use IP Identifiers

_acme4j_ supports the [ACME IP](https://tools.ietf.org/html/draft-ietf-acme-ip) extension. It permits validation of IP addresses instead of domain names. If your CA offers ACME IP support, you can add IP `Identifier` objects to the order:

```java
Order order = account.newOrder()
        .identifier(Identifier.ip(InetAddress.getByName("192.168.1.2")))
        .identifier(Identifier.dns("example.org"))
        .create();
```

The example also shows how to add domain names as DNS `Identifier` objects. Adding domain names via `domain()` is just a shortcut notation for it.

The `CSRBuilder` also accepts IP addresses for generating the CSR:

```java
CSRBuilder csrb = new CSRBuilder();
csrb.addIP(InetAddress.getByName("192.168.1.2"));
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

## Short-Term Automatic Renewal

_acme4j_ supports the [ACME STAR](https://tools.ietf.org/html/draft-ietf-acme-star) extension for short-term automatic renewal of certificates.

<div class="alert alert-warning" role="alert">

The _ACME STAR_ support is experimental. There is currently no known ACME server implementing this extension.
</div>

To find out if the CA supports the STAR extension, check the metadata:

```java
if (session.getMetadata().isStarEnabled()) {
  // CA supports STAR!
}
```

If STAR is supported, you can enable recurrent renewals by adding `recurrent()` to the order parameters:

```java
Order order = account.newOrder()
        .domain("example.org")
        .recurrent()
        .create();
```

You can use `recurrentStart()`, `recurrentEnd()`, `recurrentCertificateValidity()` and `recurrentCertificatePredate()` to change the time span and frequency of automatic renewals. You cannot use `notBefore()` and `notAfter()` in combination with `recurrent()` though.

The `Metadata` object also holds the accepted renewal limits (see `Metadata.getStarMinCertValidity()` and `Metadata.getStarMaxRenewal()`).

After the validation process is completed and the order is finalized, the STAR certificate is available via `Order.getStarCertificate()` (_not_ `Order.getCertificate()`)!

Use `Certificate.getLocation()` to retrieve the URL of your certificate. It is renewed automatically, so you will always be able to download the latest issue of the certificate from this URL.

<div class="alert alert-info" role="alert">
STAR based certificates cannot be revoked. However, as it is the nature of these certs to be short-lived, this does not pose an actual security issue.
</div>

To download the latest certificate issue, you can bind the certificate URL to your `Login` and then use the `Certificate` object.

```java
URL certificateUrl = ... // URL of the certificate

Certificate cert = login.bindCertificate(certificateUrl);
X509Certificate latestCertificate = cert.getCertificate();

```

If supported by the CA, it is possible to negotiate that the certificate can also be downloaded via `GET` request. First use `Metadata.isStarCertificateGetAllowed()` to check if this option is supported by the CA. If it is, add `recurrentEnableGet()` to the order parameters to enable it. After the order was finalized, you can use any HTTP client to download the latest certificate from the certificate URL by a `GET` request.

Use `Order.cancelRecurrent()` to terminate automatical certificate renewals.
