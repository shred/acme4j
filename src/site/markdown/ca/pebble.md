# Pebble

[Pebble](https://github.com/letsencrypt/pebble) is a small ACME test server.

This ACME provider can be used to connect to a local Pebble server instance, mainly for running integration tests.

## Connection URIs

* `acme://pebble` - Connect to a Pebble server at `localhost` and standard port 14000.
* `acme://pebble/pebble.example.com` - Connect to a Pebble server at `pebble.example.com` and standard port 14000.
* `acme://pebble/pebble.example.com:12345` - Connect to a Pebble server at `pebble.example.com` and port 12345.

Pebble uses a self-signed certificate for HTTPS connections. The Pebble provider accepts this certificate.
