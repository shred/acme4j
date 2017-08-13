# Register an Account

If it is the first time you connect to the ACME server, you need to register your account key.

To do so, create an `AccountBuilder`, optionally add some contact information, agree to the terms of service, then invoke `create()`. If the account was successfully created, you will get an `Account` object in return. Invoking its `getLocation()` method will return the location URL of your account. You should store it somewhere, because you will need it later. Unlike your key pair, the location is a public information that does not need security precautions.

```java
AccountBuilder builder = new AccountBuilder();
builder.addContact("mailto:acme@example.com");
builder.agreeToTermsOfService();

Account account = builder.create(session);

URL accountLocationUrl = account.getLocation();
```

You should not invoke `agreeToTermsOfService()` automatically, but let the user confirm the terms of service. To get a link to the current terms of services, you can invoke `session.getMetadata().getTermsOfService()`.

## Find out your account's location URL

You can also use the `AccountBuilder` to find out the location URL of your existing account:

```java
Account account = new AccountBuilder().onlyExisting().create(session);
URL accountLocationUrl = account.getLocation();
```

If you do not have an account yet, an exception is raised instead, and no new account is created.

## Update your Account

At some point, you may want to update your account. For example your contact address might have changed. To do so, invoke `Account.modify()`, perform the changes, and invoke `commit()` to make them permanent.

The following example adds another email address.

```java
account.modify()
      .addContact("mailto:acme2@example.com")
      .commit();
```

## Account Key Roll-Over

It is also possible to change the key pair that is associated with your account, for example if you suspect that your key has been compromised.

The following example changes the key pair:

```java
KeyPair newKeyPair = ... // new KeyPair to be used

account.changeKey(newKeyPair);
```

After a successful change, all subsequent calls related to this account must use the new key pair. The key is automatically updated on the `Session` that was bound to this `Account` instance.

The old key pair can be disposed of after that. However, I recommend to keep a backup of the old key pair until the key change was proven to be successful, by making a subsequent call with the new key pair. Otherwise you might lock yourself out from your account if the key change should have failed silently, for whatever reason.

## Deactivate an Account

You can deactivate your account if you don't need it any more:

```java
account.deactivate();
```

Depending on the CA, the related authorizations may be automatically deactivated as well. The certificates may still be valid until expiration or explicit revocation. If you want to make sure the certificates are invalidated as well, revoke them prior to deactivation of your account.

Be very careful: There is no way to reactivate the account once it is deactivated!
