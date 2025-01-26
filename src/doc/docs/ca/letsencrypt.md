# Let's Encrypt

Website: [Let's Encrypt](https://letsencrypt.org)

## Connection URIs

* `acme://letsencrypt.org` - Production server
* `acme://letsencrypt.org/staging` - Testing server

## Note

* Let's Encrypt does not support `Account.getOrders()`. Invocation will throw an `AcmeNotSupportedException`.