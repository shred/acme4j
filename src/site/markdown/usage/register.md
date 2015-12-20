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

## Update an Account

At some point, you may want to update your account. For example your contact address might have changed, or you were asked by the CA to accept the current terms and conditions.

To do so, create a `Registration` object again, and set the `location` property to the URI that you previously got via `newRegistration()`. Also set whatever you like to change to your account.

The following example accepts the terms and conditions by explicitly setting the URL to the agreement document.

```java
URI accountLocationUri = ... // your account's URI
URI agreementUri = ... // TAC link provided by the CA

Registration reg = new Registration();
reg.setLocation(accountLocationUri);
reg.setAgreement(agreementUri);

client.updateRegistration(account, reg);
```
