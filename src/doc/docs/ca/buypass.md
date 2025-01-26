# Buypass

Website: [Buypass](https://buypass.com/)

Available since acme4j 3.5.0

## Connection URIs

* `acme://buypass.com` - Production server
* `acme://buypass.com/staging` - Staging server

## Note

At the time of writing (September 2024), Buypass does not support the `secp384r1` ECDSA key that is generated in the [acme4j example](../example.md). You can fix this by using an RSA key, e.g.:

```java
private static Supplier<KeyPair> ACCOUNT_KEY_SUPPLIER = () -> KeyPairUtils.createKeyPair(4096);
```

## Disclaimer

_acme4j_ is not officially supported or endorsed by Buypass. If you have _acme4j_ related issues, please do not ask them for support, but [open an issue here](https://github.com/shred/acme4j/issues).
