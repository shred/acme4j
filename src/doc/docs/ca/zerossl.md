# ZeroSSL

Website: [ZeroSSL](https://zerossl.com)

Available since acme4j 3.2.0. **This provider is experimental!**

## Connection URIs

* `acme://zerossl.com` - Production server

ZeroSSL does not provide a staging server (as of February 2024).

## Note

* ZeroSSL requires account creation with [key identifier](../usage/account.md#external-account-binding).
* ZeroSSL makes use of the retry-after header, so expect that the `fetch()` methods return an `Instant`, and wait until this moment has passed (see [example](../example.md)).
* Certificate creation can take a considerable amount of time (up to 24h). The retry-after header still gives a short retry period, resulting in a very high number of status update reattempts.
* Server response can be very slow sometimes. It is recommended to set a timeout of 30 seconds or higher in the [network settings](../usage/advanced.md#network-settings).

!!! note
    If you have used the [example code](../example.md) of _acme4j_ before version 3.2.0, please review the updated example for how to use ZeroSSL with _acme4j_.

## Disclaimer

_acme4j_ is not officially supported or endorsed by ZeroSSL. If you have _acme4j_ related issues, please do not ask them for support, but [open an issue here](https://codeberg.org/shred/acme4j/issues).
