# SSL.com

Website: [SSL.com](https://ssl.com)

Available since acme4j 3.2.0. **This provider is experimental!**

## Connection URIs

* `acme://ssl.com`, `acme://ssl.com/ecc` - Production server, ECDSA certificate mode
* `acme://ssl.com/rsa` - Production server, RSA certificate mode
* `acme://ssl.com/staging`, `acme://ssl.com/staging/ecc` - Testing server, ECDSA certificate mode
* `acme://ssl.com/staging/rsa` - Testing server, RSA certificate mode

## Note

* This CA requires [External Account Binding (EAB)](../usage/account.md#external-account-binding) for account creation. However, the CA's directory resource returns `externalAccountRequired` as `false`, which is incorrect. If you use one of the `acme:` URIs above, _acme4j_ will patch the metadata transparently. If you directly connect to SSL.com via `https:` URI though, `Metadata.isExternalAccountRequired()` could return a wrong value. (As of February 2024)
* The certificate of the ssl.com staging server seems to be unmonitored. When it expires, an `AcmeNetworkException` is thrown which is caused by a `CertificateExpiredException`. There is nothing you can do to fix this error, except to ask the ssl.com support to renew the expired certificate on their server. **Please do not open an issue at acme4j.** (As of June 2024)

## Disclaimer

_acme4j_ is not officially supported or endorsed by SSL.com. If you have _acme4j_ related issues, please do not ask them for support, but [open an issue here](https://codeberg.org/shred/acme4j/issues).
