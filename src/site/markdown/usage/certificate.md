# Certificates

Once you completed all the previous steps, it's time to download the signed certificate.

```java
Order order = ... // your Order object from the previous step

order.update(); // make sure we have the current state
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
try (FileWriter fw = new FileWriter("cert-chain.crt");) {
  cert.writeCertificate(fw)
}
```

## Recreate a Certificate object
To recreate a `Certificate` object from the location, just bind it:

```java
URL locationUrl = ... // location URL from cert.getLocation()
Certificate cert = Certificate.bind(session, locationUrl);
```

## Renewal

Certificates are only valid for a limited time, and need to be renewed before expiry. To find out the expiry date of a `X509Certificate`, invoke its `getNotAfter()` method.

A certificate can be renewed a few days before its expiry. There is no explicit method for certificate renewal. To renew it, just [order](./order.html) the certificate again.

## Revocation

To revoke a certificate, just invoke the respective method:

```java
cert.revoke();
```

Optionally, you can provide a revocation reason that the ACME server may use when generating OCSP responses and CRLs.

```java
cert.revoke(RevocationReason.KEY_COMPROMISE);
```

## Revocation without account key pair

If you have lost your account key, you can still revoke a certificate as long as you still own the key pair that was used for signing the CSR. `Certificate` provides a special method for this case.

```java
URI acmeServerUri = ...     // uri of the ACME server
KeyPair domainKeyPair = ... // the key pair that was used for signing the CSR
X509Certificate cert = ...  // certificate to revoke

Certificate.revoke(acmeServerUri, domainKeyPair, cert, RevocationReason.KEY_COMPROMISE);
```

Note that there is no way to revoke a certificate if you have lost both your account's key pair and your domain's key pair.
