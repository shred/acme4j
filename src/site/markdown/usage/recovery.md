# Account Recovery

The ACME server identifies your account by the public key that you provided on registration. If you lose your key pair, you will be unable to access your account.

ACME offers two ways of recovering access to your authorizations and certificates in case you have lost your key pair. However, both ways involve creating a new account, and transfering your data to it. You will not be able to regain access to your old account.

Individual CAs may offer further ways of recovery, which are not part of this documentation.

## Contact-Based Recovery

On this recovery method, the CA contacts the account owner via one of the contact addresses given on account creation. The owner is asked to take some action (e.g. clicking on a link in an email). If it was successful, the account data is transferred to the new account.

To initiate contact-based recovery, you first need to create a new key pair and an `Account` object. Then create a `Registration` object by passing the location URI of your _old_ account to the constructor. Finally, start the recovery process by invoking `recoverRegistration()`:

```java
Account account = ... // your new account
URI oldAccountUri = ... // location of your old account

Registration reg = new Registration(oldAccountUri);
client.recoverRegistration(account, reg);

URI newAccountUri = reg.getLocation();
```

`newAccountUri` is the location URI of your _new_ account.
