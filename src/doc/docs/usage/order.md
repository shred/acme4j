# Certificate Ordering

Once you have your account set up, you are ready to order certificates.

## Creating an Order

Use `Account.newOrder()` to start ordering a new certificate. It returns an `OrderBuilder` object that helps you to collect the parameters of the order. You can give one or more domain names. Optionally you can also give your desired `notBefore` and `notAfter` dates for the generated certificate, but it is at the discretion of the CA to use (or ignore) these values.

```java
Account account = ... // your Account object

Order order = account.newOrder()
        .domains("example.org", "www.example.org", "m.example.org")
        .notAfter(Instant.now().plus(Duration.ofDays(20L)))     // optional
        .create();
```

!!! note
    The number of domains per certificate may be limited. See your CA's documentation for the limits.

## Authorization

The `Order` resource contains a collection of `Authorization` objects that can be read from the `getAuthorizations()` method.

Each `Authorization` is associated with one of the domains in your order. `Authorization.getIdentifier()` returns that identifier. Before you can retrieve your certificate, you must process _all_ authorizations that are in a `PENDING` state.

```java
for (Authorization auth : order.getAuthorizations()) {
  if (auth.getStatus() == Status.PENDING) {
    log.info("Authorizing " + auth.getIdentifier());

    // process auth by performing a challenge, see below
     :
     :
  }
}
```

If all `Authorization` objects are in status `VALID`, you are ready to [finalize your order](#finalizing-the-order).

## Challenge

The `Authorization` instance contains further details about how you can prove the ownership of your domain. An ACME server offers one or more authorization methods, called `Challenge`.

`Authorization.getChallenges()` returns a collection of all `Challenge`s offered by the CA for domain ownership validation. You only need to complete _one_ of them to successfully authorize your domain. You would usually pick the challenge that is best suited for your infrastructure.

!!! tip
    See [here](../challenge/index.md) for a description of all standard challenges. However, your CA may not offer all of the standard types, and may offer additional, proprietary challenge types.

The simplest way is to invoke `findChallenge()`, stating the challenge type your system is able to provide (either as challenge name or challenge class type):

```java
Optional<Http01Challenge> challenge = auth.findChallenge(Http01Challenge.TYPE); // by name
Optional<Http01Challenge> challenge = auth.findChallenge(Http01Challenge.class); // by type
```

It returns a properly casted `Challenge` object, or _empty_ if your challenge type was not offered by the CA. In this example, your system choses `Http01Challenge` because it is able to respond to a [http-01](../challenge/http-01.md) challenge.

!!! tip
    Passing the challenge type is preferred over the challenge name, as type checks are performed at compile time here. Passing in the challenge name might result in a `ClassCastException` at runtime.

The returned `Challenge` resource provides all the data that is necessary for a successful verification of your domain ownership (see the documentation of the individual challenges).

After you have performed the necessary steps to set up the response to the challenge (e.g. configuring your web server or modifying your DNS records), you tell the ACME server that you are ready for validation:

```java
challenge.trigger();
```

Now you have to wait for the server to check your response. If the checks are completed, the CA will set the authorization status to `VALID` or `INVALID`. The easiest (but admittedly also the ugliest) way is to poll the status:

```java
while (!EnumSet.of(Status.VALID, Status.INVALID).contains(auth.getStatus())) {
  Thread.sleep(3000L);
  auth.fetch();
}
```

This is a very simple example which can be improved in many ways:

* Limit the number of checks, to avoid endless loops if an authorization is stuck on server side.
* Wait with the status checks until the CA has accessed the response for the first time (e.g. after an incoming HTTP request to the response file).
* Use an asynchronous architecture instead of a blocking `Thread.sleep()`.
* Check if `auth.fetch()` returns a retry-after `Instant`, and wait for the next update at least until this moment is reached. See the [example](../example.md) for a simple way to do that.

The CA server may start with the validation immediately after `trigger()` is invoked, so make sure your server is ready to respond to requests before invoking `trigger()`. Otherwise the challenge might fail instantly.

Also keep your response available until the status has changed to `VALID` or `INVALID`. The ACME server may check your response multiple times, and from different IPs! If the status gets `VALID` or `INVALID`, the response you have set up before is not needed anymore. It can (and should) be removed.

!!! tip
    A common mistake is that the server infrastructure is not completely ready when `trigger()` is invoked (e.g. caches are not purged, services are still restarting, synchronization between instances is still in progress). Also, do not tear down the challenge response too early, as the CA might perform multiple checks.

If your authorization status turned to `VALID`, you have successfully authorized your domain, and you are ready for the next step.

## Finalizing the Order

After successfully completing all authorizations, the order needs to be finalized.

First of all, you will need to generate a key pair that is used for certification and encryption of the domain. Similar to the account key pair, you can either use external tool, Java's own crypto framework, or use the [`KeyPairUtils`](../acme4j-client/apidocs/org.shredzone.acme4j.utils/org/shredzone/acme4j/util/KeyPairUtils.html).

!!! tip
    Never use your account key pair as domain key pair, but always generate separate key pairs!

After that, the order can be finalized:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

order.execute(domainKeyPair);
```

_acme4j_ will automatically take care of creating a minimal CSR for this order internally. If you need to expand this CSR (e.g. with your company name), you can do so:

```java
order.execute(domainKeyPair, csr -> {
    csr.setOrganization("ACME Corp.");
});
```

It depends on the CA if other CSR properties (like _Organization_, _Organization Unit_) are accepted. Some may even require these properties to be set, while others may ignore them when generating the certificate.

You can also create a custom CSR, and pass it to the order with either `execute(PKCS10CertificationRequest csr)` or `execute(byte[] csr)`.

!!! note
    According to RFC-8555, the correct technical term is _finalization_ of an order. However, Java has a method called `Object.finalize()` which is problematic and should not be used. To avoid confusion with that method, the finalization methods are intentionally called `execute` in _acme4j_.

## Retrieving the Certificate

Once you completed all the previous steps, it is finally time to download the signed certificate.

But first we need to wait until the certificate is available for download. Again, a primitive way is to poll the status:

```java
Order order = ... // your Order object from the previous step

while (!EnumSet.of(Status.VALID, Status.INVALID).contains(order.getStatus())) {
  Thread.sleep(3000L);
  order.fetch();
}
```

This is a very simple example which can be improved in many ways:

* Limit the number of checks, to avoid endless loops if the order is stuck on server side.
* Use an asynchronous architecture instead of a blocking `Thread.sleep()`.
* Check if `order.fetch()` returns a retry-after `Instant`, and wait for the next update at least until this moment is reached. See the [example](../example.md) for a simple way to do that.

!!! tip
    If the status is `PENDING`, you have not completed all authorizations yet.

!!! note
    Always check the status before downloading the certificate, even if it seems that the CA sets the status to `VALID` immediately.

As soon as the status turns `VALID`, you can retrieve a `Certificate` object:

```java
Certificate cert = order.getCertificate();
```

The `Certificate` object offers methods to get the certificate or the certificate chain.

```java
X509Certificate cert = cert.getCertificate();
List<X509Certificate> chain = cert.getCertificateChain();
```

`cert` only contains your leaf certificate. However, most servers require the certificate `chain` that also contains all intermediate certificates up to the root CA.

You can write the certificate chain to disk using the `Certificate.writeCertificate()` method. It will create a `.crt` file that is accepted by most servers (like _Apache_, _nginx_, _postfix_, _dovecot_, etc.).

**Congratulations! You have just created your first certificate via _acme4j_.**

## List all Orders

To get a list of all current orders of your account, invoke `Account.getOrders()`.

Note that for reasons lying in the ACME protocol, the result is an `Iterator<Order>` and not a list. Also, any invocation of `Iterator.next()` can initiate a network call to the CA, and may throw an `AcmeProtocolException` if there was an error.

!!! important
    This method is a mandatory part of RFC-8555. Still, as of now, this functionality has not been implemented in all [Boulder](https://github.com/letsencrypt/boulder) based CAs (like Let's Encrypt) and will throw an `AcmeNotSupportedException`. Also see [this issue](https://github.com/letsencrypt/boulder/issues/3335). At the moment, the only workaround is to store `Order` location URLs (or other resource URLs) locally along with the certificates, see the [Resources and Persistence](./persistence.md) chapter.


## Wildcard Certificates

If supported by the CA, you can also generate a wildcard certificate that is valid for all subdomains of a domain, by prefixing the domain name with `*.` (e.g. `*.example.org`). The domain itself is not covered by the wildcard certificate and also needs to be added to the order if necessary.

!!! note
    _acme4j_ accepts all kind of wildcard notations (e.g. `www.*.example.org`, `*.*.example.org`). However, those notations are not specified. They may be rejected by the CA, or may not work as expected.

You must be able to prove ownership of the domain that you want to order a wildcard certificate for (i.e. for `*.example.org` ownership of `example.org` needs to be proven). The corresponding `Authorization` resource only refers to that domain, and does not contain the wildcard notation. However, the `Authorization.isWildcard()` method will reveal that this authorization is related to a wildcard certificate.

The following example creates an `Order` for `example.org` and `*.example.org`:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

Order order = account.newOrder()
        .domains("example.org", "*.example.org")
        .create();

order.execute(domainKeyPair);
```

In the subsequent authorization process, you would only have to prove ownership of the `example.org` domain.

!!! note
    Some CAs may reject wildcard certificate orders at all, may only offer a limited set of challenge types, or may require special challenge types that are not documented here. Refer to your CA's documentation to find out about the wildcard certificate policy.

## IP Identifiers

Besides domains, _acme4j_ also supports IP identifier validation as specified in [RFC 8738](https://tools.ietf.org/html/rfc8738). If your CA offers ACME IP support, you can add IP `Identifier` objects to the order:

```java
Order order = account.newOrder()
        .identifier(Identifier.ip(InetAddress.getByName("192.0.2.2")))
        .identifier(Identifier.ip("192.0.2.3"))   // for your convenience
        .identifier(Identifier.dns("example.org"))
        .create();
```

The example also shows how to add domain names as DNS `Identifier` objects. Adding domain names via `domain()` is just a shortcut notation for it.

## Subdomains

Ordering certificates for subdomains is not different to ordering certificates for domains. You prove ownership of that subdomain, and then get a certificate for it.

If your CA supports [RFC 9444](https://tools.ietf.org/html/rfc9444), you can also get certificates for all subdomains only by proving ownership of an ancestor domain. To do so, add the ancestor domain to your `Identifier` when creating the order:

```java
Order order = account.newOrder()
        .identifier(
            Identifier.dns("foo.bar.example.org")
                .withAncestorDomain("example.org")
        )
        .create();
```

The CA can then choose to issue challenges for any of `foo.bar.example.org`, `bar.example.org`, or `example.org`. For each challenge, the related domain can be get via `Authorization.getIdentifier()`.

`Authorization.isSubdomainAuthAllowed()` will return `true` if that `Authorization` is used to issue subdomain certificates.

To check if your CA supports RFC 9444, read `Metadata.isSubdomainAuthAllowed()`.

## Profiles

If your CA supports [draft-aaron-acme-profiles](https://www.ietf.org/archive/id/draft-aaron-acme-profiles-00.html), you can select a profile when ordering a certificate:

```java
Order order = account.newOrder()
        .profile("tlsserver")
        .create();
```

You can use `Metadata` to check if profiles are supported, and which ones:

* `Metadata.isProfileAllowed()`: `true` if profiles are supported
* `Metadata.isProfileAllowed(String)`: `true` if the given profile is supported
* `Metadata.getProfiles()`: returns a `Set` of all profile names
* `Metadata.getProfileDescription(String)`: returns a human-readable profile description
