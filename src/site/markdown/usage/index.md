# How to Use _acme4j_

_acme4j_ is a client library that helps connecting to ACME servers without worrying about specification details.

The ACME protocol uses a public key to identify your account, so the very first step is to create a key pair. You can use external tools or standard Java methods to create it. A more convenient way is to use the `KeyPairUtils` class in the `acme4j-utils` module.

This call will generate a RSA key pair with a 2048 bit key:

```java
KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
```

You can also create an elliptic curve key pair:

```java
KeyPair keyPair = KeyPairUtils.createECKeyPair("secp256r1");
```

> **CAUTION**: Your KeyPair is the only key to your account. If you should lose it, you will be locked out from your account and certificates. The API does not offer a way to recover access after a key loss. The only way is to contact the CA and ask for assistance. **It is strongly recommended to keep your key pair in a safe place!**

To save a `KeyPair` (actually, the private key of the key pair) to a pem file, use this snippet:

```java
try (FileWriter fw = new FileWriter("keypair.pem")) {
  KeyPairUtils.writeKeyPair(keyPair, fw);
}
```

The following snippet reads the private key from a pem file, and returns a `KeyPair`.

```java
try (FileReader fr = New FileReader("keypair.pem")) {
  return KeyPairUtils.readKeyPair(fr);
}
```

Now that you have created (and saved) your account's key pair, you can start with registering an account and getting your first certificate. These steps need to be performed:

* [Create a Session object](./session.html)
* [Register and Create an Account](./account.html)
* [Order a Certifiate](./order.html)
* [Download a Certificate](./certificate.html)
