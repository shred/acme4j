# Order a Certificate

Once you have your account set up, you are ready to order certificates.

## Create a Certificate Signing Request (CSR)

To do so, prepare a PKCS#10 CSR file. A single domain may be set as _Common Name_. Multiple domains must be provided as _Subject Alternative Name_. Other properties (_Organization_, _Organization Unit_ etc.) depend on the CA. Some may require these properties to be set, while others may ignore them when generating the certificate.

CSR files can be generated with command line tools like `openssl`. Unfortunately the standard Java does not offer classes for that, so you'd have to resort to [Bouncy Castle](http://www.bouncycastle.org/java.html) if you want to create a CSR programmatically. In the `acme4j-utils` module, there is a [`CSRBuilder`](../apidocs/org/shredzone/acme4j/util/CSRBuilder.html) for your convenience. You can also use [`KeyPairUtils`](../apidocs/org/shredzone/acme4j/util/KeyPairUtils.html) for generating a new key pair for your domain.

> __Important:__ Do not just use your account key pair as domain key pair, but always generate separate key pairs!

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

The generated certificate will be valid for all of the domains stored in the CSR.

> __Note:__ The number of domains per certificate may be limited. See your CA's documentation for the limits.

## Order a Certificate

The next step is to use your `Account` object to order the certificate, by using the `orderCertificate()` method. You can optionally give your desired `notBefore` and `notAfter` dates for the generated certificate, but it is at the discretion of the CA to use (or ignore) these values.

```java
Account account = ... // your Account object
byte[] csr = ...      // your CSR (see above)

Order order = account.orderCertificate(csr, null, null);
```

The `Order` resource contains a collection of `Authorization`s that can be read from the `getAuthorizations()` method. You must process _all of them_ in order to get the certificate.

## Process an Authorization

The `Authorization` instance contains further details about how you can prove ownership of your domain. An ACME server offers combinations of different authorization methods, called `Challenge`s.

`getChallenges()` returns a collection of all `Challenge`s offered by the CA for domain ownership validation. You only need to use _one_ of them to successfully authorize your domain.

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

Now you have to wait for the server to test your response and set the challenge status to `VALID`. The easiest (but admittedly also the ugliest) way is to poll the status:

```java
while (challenge.getStatus() != Status.VALID) {
    Thread.sleep(3000L);
    challenge.update();
}
```

This is a very simple example. You should limit the number of loop iterations, and always abort the loop when the status should turn to `INVALID`. If you know when the CA server actually requested your response (e.g. when you notice a HTTP request on the response file), you should start polling after that event.

The CA server may start the validation immediately after `trigger()` is invoked, so make sure your server is ready to respond to requests before invoking `trigger()`. Otherwise the challenge might fail.

`update()` may throw an `AcmeRetryAfterException`, giving an estimated instant in `getRetryAfter()` when the challenge is completed. You should then wait until that moment has been reached, before trying again. The state of your `Challenge` instance is still updated when this exception is thrown.

When the challenge status is `VALID`, you have successfully authorized your domain.

## Wildcard Certificates

You can also generate a wildcard certificate that is valid for all subdomains of a domain, by prefixing the domain name with `*.` (e.g. `*.example.org`). The domain itself is not covered by the wildcard certificate, and also needs to be added to the CSR if necessary.

You must be able to prove ownership of the domain that you want to order a wildcard certificate for. The corresponding `Authorization` resource only refers to that domain, and does not contain the wildcard notation.

The following example creates a CSR for `example.org` and `*.example.org`:

```java
KeyPair domainKeyPair = ... // KeyPair to be used for HTTPS encryption

CSRBuilder csrb = new CSRBuilder();
csrb.addDomain("example.org");    // example.org itself, if necessary
csrb.addDomain("*.example.org");  // wildcard for all subdomains
csrb.sign(domainKeyPair);
byte[] csr = csrb.getEncoded();
```

In the subsequent authorization process, you would have to prove ownership of the `example.org` domain.

> __Note:__ Some CAs may reject wildcard certificate orders, or may involve `Challenge`s that are not documented here. Refer to your CA's documentation to find out about the wildcard certificate policy.

> __Note:__ _acme4j_ accepts all kind of wildcard notations (e.g. `www.*.example.org`, `*.*.example.org`.). However, those notations are not specified and may be rejected by your CA.

## Pre-Authorize a Domain

It is possible to pro-actively authorize a domain. This can be useful to find out what challenges are requested by the CA to authorize a domain, before actually ordering a certificate. It may also help to speed up the ordering process, as already completed authorizations do not need to be completed again when ordering the certificate.

```java
Account account = ... // your Account object
String domain = ...   // Domain name to authorize

Authorization auth = account.preAuthorizeDomain(String domain);
```

> __Note:__ Some CAs may not offer domain pre-authorization. `preAuthorizeDomain()` will then fail and throw an exception.

## Deactivate an Authorization

It is possible to deactivate an `Authorization`, for example if you sell the associated domain.

```java
auth.deactivate();
```

## Restore a Challenge

Validating a challenge can take a considerable amount of time and is a candidate for asynchronous execution. This can be a problem if you need to keep the `Challenge` object for a later time or a different Java environment.

To recreate a `Challenge` object at a later time, all you need is to store the original object's `location` property:

```java
Challenge originalChallenge = ... // some Challenge instance
URL challengeUrl = originalChallenge.getLocation();
```

Later, you restore the `Challenge` object by invoking `Challenge.bind()`.

```java
URL challengeUrl = ... // challenge URL
Challenge restoredChallenge = Challenge.bind(session, challengeUrl);
```

The `restoredChallenge` already reflects the current state of the challenge.

You can also restore `Order` and `Authorization` objects at a later execution:

```java
// Get the location URL
Order originalOrder = ... // your Order instance
URL orderUrl = originalOrder.getLocation();

// Restore the order
Order restoredOrder = Order.bind(session, orderUrl);
```

```java
// Get the location URL
Authorization originalAuthorization = ... // your Authorization instance
URL authorizationUrl = originalAuthorization.getLocation();

// Restore the order
Authorization restoredAuthorization = Authorization.bind(session, authorizationUrl);
```
