# Certificates

Once you completed all the previous steps, it's time to download the signed certificate.

But first we need to wait until the certificate is available for download. Again, a primitive way is to poll the status:

```java
Order order = ... // your Order object from the previous step

while (order.getStatus() != Status.VALID) {
  Thread.sleep(3000L);
  order.update();
}
```

This is a very simple example. You should limit the number of loop iterations, and also handle the case that the status could turn to `INVALID`.

`update()` may throw an `AcmeRetryAfterException`, giving an estimated instant in `getRetryAfter()` when the certificate is available. You should then wait until that moment has been reached, before trying again. The state of your `Order` instance is still updated when this exception is thrown.

!!! tip
    If the status is `PENDING`, you have not completed all authorizations yet.

As soon as the status is `VALID`, you can retrieve a `Certificate` object:

```java
Certificate cert = order.getCertificate();
```

The `Certificate` object offers methods to get the certificate or the certificate chain.

```java
X509Certificate cert = cert.getCertificate();
List<X509Certificate> chain = cert.getCertificateChain();
```

`cert` only contains the plain certificate. However, most servers require the certificate `chain` that also contains all intermediate certificates up to the root CA.

Congratulations! You have just created your first certificate via _acme4j_.

## Save the Certificate

The `Certificate` object provides a method to write a certificate file that can be used for most web servers, like _Apache_, _nginx_, but also other servers like _postfix_ or _dovecot_:

```java
try (FileWriter fw = new FileWriter("cert-chain.crt")) {
  cert.writeCertificate(fw)
}
```

## Renewal

Certificates are only valid for a limited time, and need to be renewed before expiry.

!!! tip
    You can find out the expiry date of a `X509Certificate` by invoking its `getNotAfter()` method.

A certificate can be renewed a few days before its expiry. There is no explicit method for certificate renewal. To renew it, just [order](order.md) the certificate again.

## Revocation

To revoke a certificate, just invoke the respective method:

```java
cert.revoke();
```

Optionally, you can provide a revocation reason that the ACME server may use when generating OCSP responses and CRLs.

```java
cert.revoke(RevocationReason.KEY_COMPROMISE);
```

If you cannot create a `Certificate` object because you don't know the certificate's location URL, you can also use an alternative method that only requires a `Login` and the certificate itself:

```java
Login login = ...           // login to your account
X509Certificate cert = ...  // certificate to revoke

Certificate.revoke(login, cert, RevocationReason.KEY_COMPROMISE);
```

## Revocation without Account Key Pair

If you have lost your account key, you can still revoke a certificate as long as you still own the domain key pair that was used for signing the CSR. `Certificate` provides a special method for this case.

```java
KeyPair domainKeyPair = ... // the key pair that was used for signing the CSR
X509Certificate cert = ...  // certificate to revoke

Certificate.revoke(session, domainKeyPair, cert, RevocationReason.KEY_COMPROMISE);
```

!!! warning
    There is no way to revoke a certificate if you have lost both your account's key pair and your domain's key pair.
