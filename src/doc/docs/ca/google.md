# Google

Web site: [Google Trust Services](https://pki.goog/)

Available since acme4j 3.5.0

## Connection URIs

* `acme://pki.goog` - Production server
* `acme://pki.goog/staging` - Staging server

## Note

_Google Trust Services_ requires account creation with [External Account Binding](../usage/account.md#external-account-binding). See [this tutorial](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial) about how to create the EAB secrets. You will get a `keyId` and a `b64MacKey` that can be directly passed into `AccountBuilder.withKeyIdentifier()`.

!!! note
    You cannot use the production EAB secrets for accessing the staging server, but you need separate secrets! Please read the respective chapter of the tutorial about how to create them.

_Google Trust Services_ request `HS256` as MAC algorithm. If you use the connection URIs above, this is set automatically. If you use a `https` connection URI, you will need to set the MAC algorithm manually by adding `withMacAlgorithm("HS256")` to the `AccountBuilder`.

## Disclaimer

_acme4j_ is not officially supported or endorsed by Google. If you have _acme4j_ related issues, please do not ask them for support, but [open an issue here](https://github.com/shred/acme4j/issues).
