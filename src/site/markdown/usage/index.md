# How to Use _acme4j_

_acme4j_ is a client library that helps connecting to ACME servers without worrying about specification details.

Central part of the communication is a [`Registration`](../apidocs/org/shredzone/acme4j/Registration.html) object, which contains a key pair. The ACME server identifies your account by the public key, and verifies that your requests are signed with your private key. For this reason, you should keep the key pair in a safe place. If you should lose it, you would need to recover access to your account.

The first step is to create a Java `KeyPair`, save it somewhere, and then pass it to the constructor of `Registration`:

```java
KeyPair keypair = ... // your key pair
Registration registration = new Registration(keypair);
```

You need this `Registration` instance as identifier for almost all API calls.

Some calls additionally need the registration location URI to be set. You can either set it after construction, or use the constructor that also accepts the location URI:

```java
KeyPair keypair = ... // your key pair
URI accountLocationUri = ... // your account's URI, as returned by newRegistration()

Registration registration1 = new Registration(keypair, accountLocationUri);

Registration registration2 = new Registration(keypair);
registration2.setLocation(accountLocationUri);
```

To get a certificate, these steps need to be performed:

* [Connect to an ACME server](./connect.html)
* [Register and Create an Account](./register.html)
* [Authorize your Domains](./authorization.html)
* [Request and Download a Certificate](./certificate.html)
