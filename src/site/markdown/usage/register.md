# Register an Account

The first thing to do is to register your account key with the CA.

You need a `Registration` instance that serves as a data transfer object, and fill the object with details of your account. The `AcmeClient.newRegistration()` call then completes the data transfer object with server side account data.

This code fragment registers your account with the CA. Optionally you can add contact URIs (like email addresses or phone numbers) to the registration, which will help the CA getting in contact with you.

```java
KeyPair keyPair = ... // your account KeyPair
Registration reg = new Registration(keypair);
reg.addContact("mailto:acme@example.com"); // optional

client.newRegistration(reg);

URI accountLocationUri = reg.getLocation(); // your account's server URI
```

After invocating `newRegistration()`, the `location` property contains the URI of your newly created account on server side. You should copy the `location` to a safe place. You will need it again if you need to [update your registration](#Update_your_Registration), or if you need to [recover](./recovery.html) access to your account after you have lost your account key. Unlike your key pair, the `location` is a public information that does not need security precautions.

`newRegistration()` may fail and throw an `AcmeException` for various reasons. When your public key was already registered with the CA, an `AcmeConflictException` is thrown, but the `location` property will still hold your account URI after the call. This may be helpful if you forgot your account URI and need to recover it.

## Update your Registration

At some point, you may want to update your registration. For example your contact address might have changed, or you were asked by the CA to accept the latest terms of service.

To do so, create a `Registration` object again, this time by passing in the account key pair and the `location` property that you previously got via `newRegistration()`. Also set whatever you like to change to your account.

The following example accepts the terms of service by explicitly setting the URL to the agreement document.

```java
KeyPair keyPair = ... // your account KeyPair
URI accountLocationUri = ... // your account's URI

URI agreementUri = ... // TAC link provided by the CA

Registration reg = new Registration(keyPair, accountLocationUri);
reg.setAgreement(agreementUri);

client.modifyRegistration(reg);
```

## Account Key Roll-Over

> **CAUTION**: Account Key Roll-Over is currently not supported by _Let's Encrypt_. It silently ignores your new key, and gives you the fatal impression that you can safely dispose your old key after that.

It is also possible to change the key pair that is associated with your account, for example if you suspect that your key has been compromised.

The following example changes the key pair:

```java
KeyPair oldKeyPair = ... // your old KeyPair that is to be replaced
URI accountLocationUri = ... // your account's URI

Registration reg = new Registration(oldKeyPair, accountLocationUri);

KeyPair newKeyPair = ... // new KeyPair to be used

client.changeRegistrationKey(reg, newKeyPair);
```

All subsequent calls must now use the new key pair. The old key pair can be disposed.
