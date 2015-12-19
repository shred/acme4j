# How to Use _acme4j_

_acme4j_ is a client library that helps connecting to ACME servers without worrying about specification details.

Central part of the communication is an [`Account`](../apidocs/org/shredzone/acme4j/Account.html) object, which contains a key pair. The ACME server identifies your account by the public key, and verifies that your requests are signed with your private key. For this reason, you should keep the key pair in a safe place. If you should lose it, you would need to recover access to your account.

The first step is to create a Java `KeyPair`, save it somewhere, and then pass it to the constructor of `Account`:

```java
KeyPair keypair = ... // your key pair
Account account = new Account(keypair);
```

You need this `Account` instance as identifier for almost all API calls.

To get a certificate, these steps need to be performed:

* [Connect to an ACME server](./connect.html)
* [Register and Create an Account](./register.html)
* [Authorize your Domains](./authorization.html)
* [Request and Download a Certificate](./certificate.html)
