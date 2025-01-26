# Pebble

[Pebble](https://github.com/letsencrypt/pebble) is a small ACME test server.

This ACME provider can be used to connect to a local Pebble server instance, mainly for running integration tests.

## Connection URIs

* `acme://pebble` - Connect to a Pebble server at `localhost` and standard port 14000.
* `acme://pebble:12345` - Connect to a Pebble server at `localhost` and port 12345.
* `acme://pebble/pebble.example.com` - Connect to a Pebble server at `pebble.example.com` and standard port 14000.
* `acme://pebble/pebble.example.com:12345` - Connect to a Pebble server at `pebble.example.com` and port 12345.

Pebble uses a self-signed certificate for HTTPS connections. The Pebble provider accepts this certificate.

## Different Host Name

The Pebble server provides an end-entity certificate for the `localhost` and `pebble` domain.

If your Pebble server can be reached at a different domain (like `pebble.example.com` above), you need to create a correct end-entity certificate on your Pebble server. [See here](https://github.com/letsencrypt/pebble/tree/main/test/certs) for how to use `minica` to create a matching certificate.

Otherwise, you will get an `AcmeNetworkException: Network error` that is caused by a `java.io.IOException: No subject alternative DNS name matching [...] found` when trying to access the Pebble server.

If you cannot create a correct end-entity certificate on your Pebble server, you could also disable host name verification on Java side: `-Djdk.internal.httpclient.disableHostnameVerification`

!!! warning
    **Disable hostname verification for testing purposes only, never in a production environment!** Create a correct end-entity certificate whenever possible.

## Custom CA Certificate

Pebble provides a default CA certificate, which can be found at `test/certs/pebble.minica.pem` of the Pebble server. This default CA is integrated into _acme4j_'s Pebble provider, and is automatically accepted.

If you run a Pebble instance with a custom `pebble.minica.pem`, copy your PEM file as a resource to your project (either in the `src/test/resources` or `src/test/resources/META-INF` folder).
