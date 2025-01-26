# Certificate Revocation

To revoke a certificate, just invoke the respective method:

```java
cert.revoke();
```

Optionally, you can provide a revocation reason that the ACME server may use when generating OCSP responses and CRLs.

```java
cert.revoke(RevocationReason.KEY_COMPROMISE);
```

There are different reasons for a certificate revocation. If you have sold or deleted the associated domain, you should also deactivate the respective `Authorization` using `Authorization.deactivate()`. Otherwise, the new owner of the domain might have problems to get a certificate because the domain name is still associated with your account.

!!! tip
    It is not documented if the deactivation of an authorization also revokes the related certificate automatically. If in doubt, revoke the certificate yourself before deactivation.

## Without Certificate URL

If you cannot create a `Certificate` object because you don't know the certificate's location URL, you can also use an alternative method that only requires a `Login` and the certificate itself:

```java
Login login = ...           // login to your account
X509Certificate cert = ...  // certificate to revoke

Certificate.revoke(login, cert, RevocationReason.KEY_COMPROMISE);
```

## Without Account Key

If you have lost your account key, you can still revoke a certificate as long as you still own the domain key pair that was used for the order. `Certificate` provides a special method for this case.

```java
KeyPair domainKeyPair = ... // the key pair used for order (not your account key pair)
X509Certificate cert = ...  // certificate to revoke

Certificate.revoke(session, domainKeyPair, cert, RevocationReason.KEY_COMPROMISE);
```

!!! warning
    There is no automatized way to revoke a certificate if you have lost both your account's key pair and your domain's key pair.
