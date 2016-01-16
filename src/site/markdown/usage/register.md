# Register an Account

The first thing to do is to register your `Account` with the CA.

You need a `Registration` instance that serves as a data transfer object, and fill the object with details of your account. The `AcmeClient.newRegistration()` call then completes the data transfer object with server side account data.

This code fragment registers your account with the CA. Optionally you can add contact URIs (like email addresses or phone numbers) to the registration, which will help the CA getting in contact with you.

```java
Registration reg = new Registration();
reg.addContact("mailto:acme@example.com"); // optional

client.newRegistration(account, reg);

URI accountLocationUri = reg.getLocation(); // your account's server URI
```

After invocating `newRegistration()`, the `location` property contains the URI of your newly created account on server side.

`newRegistration()` may fail and throw an `AcmeException` for various reasons. When your public key was already registered with the CA, an `AcmeConflictException` is thrown, but the `location` property will still hold your account URI after the call. This may be helpful if you forgot your account URI and need to recover it.

You should always copy the `location` to a safe place. If you should lose your key pair, you will need it to [recover](./recovery.html) access to your account. Unlike your key pair, the `location` is an information that does not need security precautions.

## Update an Account

At some point, you may want to update your account. For example your contact address might have changed, or you were asked by the CA to accept the current terms of service.

To do so, create a `Registration` object again, and set the `location` property to the URI that you previously got via `newRegistration()`. Also set whatever you like to change to your account.

The following example accepts the terms of service by explicitly setting the URL to the agreement document.

```java
URI accountLocationUri = ... // your account's URI
URI agreementUri = ... // TAC link provided by the CA

Registration reg = new Registration();
reg.setLocation(accountLocationUri);
reg.setAgreement(agreementUri);

client.modifyRegistration(account, reg);
```

## Account Key Roll-Over

It is also possible to change the key pair that is associated with your account, for example if you suspect that your key has been compromised.

The following example changes the key pair:

```java
Registration reg = new Registration();
reg.setLocation(accountLocationUri);

KeyPair newKeyPair = ... // new KeyPair to be used

client.changeRegistrationKey(account, reg, newKeyPair);
```

All subsequent calls must now use an `Account` instance with the new key. The old key can be disposed.
