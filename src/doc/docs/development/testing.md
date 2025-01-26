# Testing acme4j

## Integration Tests

_acme4j_ provides a number of integration tests. These tests are _not_ executed by maven by default, as they require Docker on the build machine.

To run them, install Docker and make it available to your user. Then invoke `mvn -Pci verify` to run the integration tests.

The integration tests use the [latest docker image](https://hub.docker.com/r/letsencrypt/pebble) of the [Pebble ACME test server](https://github.com/letsencrypt/pebble) in a container named _pebble_. A second docker container named _bammbamm_ uses [pebble-challtestsrv](https://hub.docker.com/r/letsencrypt/pebble-challtestsrv) as a test server. Pebble connects to this test server for resolving domain names and for the verification of challenges.

If you change into the `acme-it` module's directory, you can also build, start and stop the test servers with `mvn docker:build`, `mvn docker:start` and `mvn docker:stop`, respectively. While the test servers are running, you can run the integration tests in your IDE. `mvn docker:remove` finally removes the test server images.

If you like to change the default configuration of the integration tests (e.g. because you are running _pebble_ and _pebble-challtestsrv_ instances on a dedicated test server), you can do so by changing these system properties:

* `pebbleHost`: Host name of the pebble server. Default: `localhost`
* `pebblePort`: Port the pebble server is listening on. Default: 14000
* `bammbammUrl`: URI of the _pebble-challtestsrv_ to connect to. Default: `http://localhost:8055`

!!! warning
    _pebble-challtestsrv_ is meant for testing purposes only. Only use it in secured testing environments. The server is neither hardened nor does it offer any kind of authentication.

## Boulder

It is also possible to run some tests against the [Boulder](https://github.com/letsencrypt/boulder) ACME server, but the setup is a little tricky.

First, build and start the integration test Docker containers as [explained above](#Integration_Tests). When the servers are started, find out the IP address of the _bammbamm_ server:

```bash
docker inspect bammbamm -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

Now set up a Docker instance of Boulder. Follow the instructions in the [Boulder README](https://github.com/letsencrypt/boulder#quickstart). When you are ready to start it, set the `FAKE_DNS` env variable to the IP address of _bammbamm_ you have found before.

The Boulder integration tests can now be run with `mvn -P boulder verify`.

For a local Boulder installation, just make sure that `FAKE_DNS` is set to `127.0.0.1`. You'll also need to expose the ports 5001 and 5002 of _bammbamm_ by changing the `acme4j-it/pom.xml` accordingly.
