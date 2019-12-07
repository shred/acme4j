# Register a new Account

The first step is to register an account with the CA.

Your account needs a key pair. The public key is used to identify your account, while the private key is used to sign the requests to the ACME server.

!!! note
    Your private key is never transmitted to the ACME server.

After the CA has created your account, it returns an account URL. You will need both the key pair and the account URL for logging into the account later.

## Creating an Account Key Pair

You can use external tools like `openssl` or standard Java methods to create a key pair.

A more convenient way is to use the `KeyPairUtils` class in the `acme4j-utils` module. This call generates a RSA key pair with a 2048 bit key:

```java
KeyPair accountKeyPair = KeyPairUtils.createKeyPair(2048);
```

You can also create an elliptic curve key pair:

```java
KeyPair accountKeyPair = KeyPairUtils.createECKeyPair("secp256r1");
```

!!! danger
    Your key pair is the only way to access your account. If you should lose it, you will be locked out from your account and certificates. The API does not offer a way to recover access after a key loss. The only way is to contact the CA and hope for assistance. For this reason, it is strongly recommended to keep the key pair in a safe place!

To save a `KeyPair` (actually, the private key of the key pair) to a pem file, you can use this snippet:

```java
try (FileWriter fw = new FileWriter("keypair.pem")) {
  KeyPairUtils.writeKeyPair(accountKeyPair, fw);
}
```

The following snippet reads the private key from a pem file, and returns a `KeyPair`.

```java
try (FileReader fr = New FileReader("keypair.pem")) {
  return KeyPairUtils.readKeyPair(fr);
}
```

## Register an Account

Now create an `AccountBuilder`, optionally add some contact information, agree to the terms of service, set the key pair, then invoke `create()`:

```java
Account account = new AccountBuilder()
        .addContact("mailto:acme@example.com")
        .agreeToTermsOfService()
        .useKeyPair(keyPair)
        .create(session);

URL accountLocationUrl = account.getLocation();
```

If the account was successfully created, you will get an `Account` object in return. Invoking its `getLocation()` method will return the location URL of your account. Unlike your key pair, the location is a public information that does not need security precautions.

Now you have a key pair and the account's location URL. This is all you need for [logging in](login.md).

!!! note
    Even if it is tempting to do so, you should not invoke `agreeToTermsOfService()` automatically, but let the user confirm the terms of service first. To get a link to the current terms of service, you can invoke `session.getMetadata().getTermsOfService()`.

If the CA changes the terms of service and requires an explicit agreement to the new terms, an `AcmeUserActionRequiredException` is thrown. Its `getInstance()` method returns the URL of a document that gives instructions about how to agree to the new terms of service. There is no way to automatize this process.

## Find out your Account's Location URL

If you only have your account's `KeyPair`, you can use the `AccountBuilder` to find out the location `URL` of your account.

```java
Account account = new AccountBuilder()
        .onlyExisting()         // Do not create a new account
        .useKeyPair(keyPair)
        .create(session);

URL accountLocationUrl = account.getLocation();
```

If you do not have an account yet, an exception is raised instead, and no new account is created.

You can recover your account URL that way, but remember that is is not possible to recover your account's key pair.

## Update your Account

At some point, you may want to update your account. For example your contact address might have changed. To do so, invoke `Account.modify()`, perform the changes, and invoke `commit()` to make them permanent.

The following example adds another email address.

```java
account.modify()
      .addContact("mailto:acme2@example.com")
      .commit();
```

You can also get the list of contacts via` getContacts()`, and modify or remove contact `URI`s there. However, some CAs do not allow to remove all contacts.

## Account Key Roll-Over

It is also possible to change the key pair that is associated with your account, for example if you suspect that your key has been compromised.

The following example changes the key pair:

```java
KeyPair newKeyPair = ... // new KeyPair to be used

account.changeKey(newKeyPair);
```

After a successful change, all subsequent calls related to this account must use the new key pair. The key is automatically updated on the `Login` that is bound to this `Account` instance.

The old key pair can be disposed of after that. However, I recommend to keep a backup of the old key pair until the key change was proven to be successful, by making a subsequent call with the new key pair. Otherwise you might lock yourself out from your account if the key change should have failed silently, for whatever reason.

## Deactivate an Account

You can deactivate your account if you don't need it any more:

```java
account.deactivate();
```

Depending on the CA, the related authorizations may be automatically deactivated as well. The certificates may still be valid until expiration or explicit revocation. If you want to make sure the certificates are invalidated as well, revoke them prior to deactivation of your account.

!!! danger
    There is no way to reactivate the account once it is deactivated!

## Custom Key Identifier

Some CAs may require you to send a custom Key Identifier, to associate your ACME account with an existing customer account at your CA. The CA indicates that a custom key identifier is required if `session.getMetadata().isExternalAccountRequired()` returns `true`.

Your CA provides you with a _Key Identifier_ and a _MAC Key_ for this purpose. You can pass it to the builder using the `withKeyIdentifier()` method:

```java
String kid = ... // Key Identifier
SecretKey macKey = ... // MAC Key

Account account = new AccountBuilder()
        .agreeToTermsOfService()
        .withKeyIdentifier(kid, macKey)
        .useKeyPair(keyPair)
        .create(session);
```

For your convenience, you can also pass a base64 encoded MAC Key as `String`.
