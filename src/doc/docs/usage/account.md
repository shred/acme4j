# Account and Login

If it is the first time you interact with the CA, you will need to register an account first.

Your account requires a key pair. The public key is used to identify your account, while the private key is used to sign the requests to the ACME server.

!!! note
    The private key is never transmitted to the ACME server.

You can use external tools like `openssl` or standard Java methods to create the key pair. A more convenient way is to use the `KeyPairUtils` class. This call generates an RSA key pair with a 2048-bit key:

```java
KeyPair accountKeyPair = KeyPairUtils.createKeyPair(2048);
```

You can also create an elliptic curve key pair:

```java
KeyPair accountKeyPair = KeyPairUtils.createECKeyPair("secp256r1");
```

The key pair can be saved to a PEM file using `KeyPairUtils.writeKeyPair()`, and read back later using `KeyPairUtils.readKeyPair()`.

!!! danger
    Your key pair is the only way to access your account. **If you should lose it, you will be locked out from your account and certificates.** The API does not offer a way to recover access after a key loss. The only way is to contact the CA's support and hope for assistance. For this reason, it is strongly recommended to keep a copy of the key pair in a safe place!

## Creating an Account

The `AccountBuilder` will take care for creating a new account. Instantiate a builder, optionally add some contact information, agree to the terms of service, set the key pair, then invoke `create()`:

```java
Account account = new AccountBuilder()
        .addContact("mailto:acme@example.com")
        .agreeToTermsOfService()
        .useKeyPair(keyPair)
        .create(session);

URL accountLocationUrl = account.getLocation();
```

!!! note
    Even if it is tempting to do so, you should not invoke `agreeToTermsOfService()` automatically, but let the user confirm the terms of service first. To get a link to the current terms of service, you can invoke `session.getMetadata().getTermsOfService()`.

If the account was successfully created, you will get an `Account` object in return. Invoking its `getLocation()` method will return the location URL of your account.

It is recommended to store the location URL along with your key pair. While this is not strictly necessary, it will make it much easier to log into the account later. Unlike your key pair, the location does not need security precautions. The location can [easily be recovered if lost](#login-without-account-url).

## External Account Binding

At some CAs, you need to create a customer account on their website first, and associate it with your ACME account and key pair later. The CA indicates that this process is required if `session.getMetadata().isExternalAccountRequired()` returns `true`.

In this case, your CA provides you a _Key Identifier_ (or _KID_) and a _MAC Key_ (or _HMAC Key_). You can pass these credentials to the builder using the `withKeyIdentifier()` method:

```java
String kid = ... // Key Identifier
SecretKey macKey = ... // MAC Key

Account account = new AccountBuilder()
        .agreeToTermsOfService()
        .withKeyIdentifier(kid, macKey)
        .useKeyPair(keyPair)
        .create(session);

URL accountLocationUrl = account.getLocation();
```

For your convenience, you can also pass a base64 encoded MAC Key as `String`.

!!! note
    The MAC algorithm is automatically derived from the size of the MAC key. If a different algorithm is required, it can be set using `withMacAlgorithm()`.

## Login

After creating an account, you need to log in into it. You get a `Login` object by providing your account information to the session:

```java
KeyPair accountKeyPair = ... // account's key pair
URL accountLocationUrl = ... // account's URL

Login login = session.login(accountLocationUrl, accountKeyPair);
```

Creating a `Login` object is very cheap. You can always create and dispose them as needed. There is no need to cache or pool them.

!!! tip
    It is possible to have multiple parallel `Login`s into different accounts in a single session. This is useful if your software handles the certificates of more than one account.

## Login on Creation

If it is more convenient, you can also get a ready to use `Login` object from the `AccountBuilder` when creating a new account:

```java
Login login = new AccountBuilder()
        .addContact("mailto:acme@example.com")
        .agreeToTermsOfService()
        .useKeyPair(keyPair)
        .createLogin(session);

URL accountLocationUrl = login.getAccountLocation();
```

## Login without Account URL

As mentioned above, you will need your account key pair and the account URL for logging in. If you do not know the URL, you can log into your account by creating a new account with the same key pair. The CA will detect that an account with that key is already present, and return the existing one instead.

To avoid that an actual new account is created by accident, you can use the `AccountBuilder.onlyExisting()` method:

```java
Login login = new AccountBuilder()
        .onlyExisting()         // Do not create a new account
        .agreeToTermsOfService()
        .useKeyPair(keyPair)
        .createLogin(session);

URL accountLocationUrl = login.getAccountLocation();
```

It will return a `Login` object just from your key pair, or throw an error if the key was not known to the server.

Remember that there is no way to log into your account without the key pair! 

## Updating the Contacts

At some point, you may want to update your account. For example your contact address might have changed. To do so, invoke `Account.modify()`, perform the changes, and invoke `commit()` to make them permanent.

The following example adds another email address.

```java
Account account = login.getAccount();

account.modify()
      .addContact("mailto:acme2@example.com")
      .commit();
```

You can also get the list of contacts via `getContacts()`, and modify or remove contact `URI`s there. However, some CAs do not allow removing all contacts.

!!! note
    `AccountBuilder` only accepts contact addresses when a _new account_ is created. To modify an existing account, use `Account.modify()` as described in this section. It is not possible to modify the account using the `AccountBuilder` on an existing account.

## Changing the Account Key

It is recommended to change the account key from time to time, e.g. if you suspect that your key has been compromised, or if a staff member with knowledge of the key has left the company.

To change the key pair that is associated with your account, you can use the `Account.changeKey()` method:

```java
KeyPair newKeyPair = ... // new KeyPair to be used

Account account = login.getAccount();
account.changeKey(newKeyPair);
```

After a successful change, all subsequent calls related to this account must use the new key pair. The key is automatically updated on the `Login` that was bound to this `Account` instance, so it can be used further. Other existing `Login` instances to the account need to be recreated.

The old key pair can be disposed of after that. However, better keep a backup of the old key pair until the key change was proven to be successful, by making a subsequent call with the new key pair. Otherwise, you might lock yourself out from your account if the key change should have failed silently, for whatever reason.

## Account Deactivation

You can deactivate your account if you don't need it anymore:

```java
account.deactivate();
```

Depending on the CA, the related authorizations may be automatically deactivated as well. If you want to be on the safe side, you can deactivate all authorizations manually, using `Authorization.deactivate()`.

The issued certificates may still be valid until expiration or explicit revocation. If you want to make sure the certificates are invalidated as well, [revoke](revocation.md) them prior to deactivation of your account.

!!! danger
    There is no way to reactivate the account once it has been deactivated!
