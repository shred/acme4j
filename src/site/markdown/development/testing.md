# Testing _acme4j_

## Integration Tests

_acme4j_ provides a number of integration tests. These tests are _not_ executed by maven by default, as they require Docker on the build machine.

To run them, install Docker and make it available to your user. Then invoke `mvn -Pci verify` to run the integration tests. The test will build images of the current [Pebble ACME test server](https://github.com/letsencrypt/pebble), and an internal test server that provides a configurable HTTP and DNS server for Pebble.

If you change into the `acme-it` project directory, you can also build, start and stop the test servers with `mvn docker:build`, `mvn docker:start` and `mvn docker:stop`, respectively. While the test servers are running, you can also run the integration tests in your IDE. `mvn docker:remove` finally removes the test server images.

## BammBamm

The `acme4j-it` module contains a small and very simple test server called _BammBamm_, which can be used to verify challenges. In the default configuration, it uses these ports:

* 14001: Provides a simple REST-like interface for adding and removing challenge tokens and DNS records. This port is exposed.
* 53 (UDP): A simple DNS server for resolving test domain names, and providing `TXT` records for `dns-01` challenges.
* 5001: A simple HTTP server that responses with certificates for `tls-sni-02` challenges.
* 5002: A simple HTTP server that responses with tokens for `http-01` challenges.

To run this server, you can use the Docker image mentioned above. You could also run the server directly, but since the DNS server is listening on a privileged port, it would need to be reconfigured first.

The `BammBammClient` class can be used to set the challenge responses and DNS records via the REST interface on port 14001.

Note that _BammBamm_ has its main focus on simplicity, and is only meant as a server for integration test purposes. Do not use _Bammbamm_ in production environments! It is neither hardened, nor feature complete.

## Boulder

It is also possible to run some tests against the [Boulder](https://github.com/letsencrypt/boulder) ACME server, but the setup is a little tricky.

First, build and start the integration test Docker servers as [explained above](#Integration_Tests). When the servers are started, find out the IP address of the _BammBamm_ server (`docker inspect bammbamm -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`). You'll need it in the next step.

Now set up a Docker instance of Boulder. Follow the instructions in the [Boulder README](https://github.com/letsencrypt/boulder#quickstart). When you are ready to start it, set the `FAKE_DNS` env variable to the IP address of _BammBamm_ you have found before.

The Boulder integration tests can now be run with `mvn -P boulder verify`.

For a local Boulder installation, just make sure that `FAKE_DNS` is set to `127.0.0.1`. You'll also need to expose the ports 5001 and 5002 of _BammBamm_ by changing the `acme4j-it/pom.xml` accordingly.
