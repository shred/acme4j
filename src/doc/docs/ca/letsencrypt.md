# Let's Encrypt

Website: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server

## Note

* Let's Encrypt does not support `Account.getOrders()`, although it's required by RFC8555. Invocation will throw an `AcmeNotSupportedException`. See [this issue](https://github.com/letsencrypt/boulder/issues/3335) for more information.