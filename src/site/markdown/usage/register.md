# Register an Account

If it is the first time you connect to the ACME server, you need to register your account key.

To do so, create a `RegistrationBuilder`, optionally add some contact information, then invoke `create()`. If the account was successfully created, you will get a `Registration` object in return. Invoking its `getLocation()` method will return the location URI of your account. You should store it somewhere, because you will need it later. Unlike your key pair, the location is a public information that does not need security precautions.

```java
RegistrationBuilder builder = new RegistrationBuilder();
builder.addContact("mailto:acme@example.com");

Registration registration = builder.create(session);

URI accountLocationUri = registration.getLocation();
```

`create()` will fail and throw an `AcmeConflictException` if your key was already registered with the CA. The `AcmeConflictException` contains the location of the registration. This may be helpful if you forgot your account URI and need to recover it.

The following example will create a new `Registration` and restore an existing `Registration`.

```java
Registration registration;
try {
  registration = new RegistrationBuilder().create(session);
} catch (AcmeConflictException ex) {
  registration = Registration.bind(session, ex.getLocation());
}
```

## Update your Registration

At some point, you may want to update your registration. For example your contact address might have changed, or you were asked by the CA to accept the latest terms of service. To do so, invoke `Registration.modify()`, perform the changes, and invoke `commit()` to make them permanent.

The following example accepts the terms of service by explicitly setting the URL to the agreement document.

```java
URI agreementUri = ... // TAC link provided by the CA

registration.modify()
      .setAgreement(agreementUri)
      .commit();
```

## Account Key Roll-Over

It is also possible to change the key pair that is associated with your account, for example if you suspect that your key has been compromised.

The following example changes the key pair:

```java
KeyPair newKeyPair = ... // new KeyPair to be used

registration.changeKey(newKeyPair);
```

After a successful change, all subsequent calls related to this account must use the new key pair. The key is automatically updated on the `Session` that was bound to this `Registration`.

The old key pair can be disposed of after that. However, I recommend to keep a backup of the old key pair until the key change was proven to be successful, by making a subsequent call with the new key pair. Otherwise you might lock yourself out from your account if the key change should have failed silently, for whatever reason.

## Deactivate an Account

You can deactivate your account if you don't need it any more:

```java
registration.deactivate();
```

Depending on the CA, the related authorizations may be automatically deactivated as well. The certificates may still be valid until expiration or explicit revocation. If you want to make sure the certificates are invalidated as well, revoke them prior to deactivation of your account.

Be very careful: There is no way to reactivate the account once it is deactivated!
