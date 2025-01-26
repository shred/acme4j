# Debugging

The code base of _acme4j_ is mature and in active use for many years. There are frequent automatic integration tests running against a testing server that cover the entire process of ordering a certificate. For this reason, it is rather unlikely that _acme4j_ has an undetected major bug if used in a standard environment.

However, problems **may** occur if _acme4j_ is used in a non-standard environment. This can be (but is not limited to):

- Compatibility issues when connecting to other CA implementations than [Boulder](https://github.com/letsencrypt/boulder) and [Pebble](https://github.com/letsencrypt/pebble).
- Using other means for creating key pairs and CSRs than given in the [example](example.md).
- Using features of _acme4j_ that are declared as experimental.
- Running _acme4j_ on a different Java runtime environment than OpenJDK.
- Using _acme4j_ in a complex network architecture.

_acme4j_ offers extensive debug logging that logs the client-server communication and every important aspect of the workflow. If you are stuck with a strange behavior, the first thing you should do is to enable debug logging, and check if the client-server communication gives a hint about the problem.

## Enable Debug Logging

_acme4j_ uses the [SLF4J](https://www.slf4j.org/) framework for logging. SLF4J is a logging _facade_. The actual logging is done by other logging frameworks, and depends on your local configuration.

To enable debug logging, lower the minimum log level of the `org.shredzone.acme4j` package to `debug`.

If you use the SLF4J simple logger, which just logs to `System.err`, this can be accomplished with a simple Java command line option:

```sh
java -Dorg.slf4j.simpleLogger.log.org.shredzone.acme4j=debug ...
```

For other logging frameworks, please check the framework documentation.

Android does not log SLF4J output by default. To enable debug logging to logcat, you can add [Noveo Group's android-logger](https://noveogroup.github.io/android-logger/) to your app dependencies.

!!! warning
    _acme4j_'s debug log level never logs information that might compromise your account or your certificates, like private keys. What it **does** log though are public keys, resource location URLs, nonces, contact URIs, domain names, challenges (and their responses), CSRs, certificates, and other sensitive data. For this reason, it is recommended to keep debug logging disabled on production machines.
    
    **Do not blindly post debug logs to public bug reports or questions!**

Understanding the debug log output requires some basic knowledge about the [RFC 8555](https://tools.ietf.org/html/rfc8555) protocol. If you need assistance with your problem, don't hesitate to [open an issue](https://github.com/shred/acme4j/issues).

## Example Log Output

This is an example debug log output for creating a new account. This example connects to a [Pebble](https://github.com/letsencrypt/pebble) test server instance running locally on port 14000, so the CA's base URL is `https://localhost:14000`.

Usually _acme4j_ first logs the action that is taken:

```text
[main] DEBUG org.shredzone.acme4j.AccountBuilder - create
```

If there is no cached copy of the CA's directory, it is fetched now.

```text
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - GET https://localhost:14000/dir
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Cache-Control: public, max-age=0, no-cache
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Length: 406
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Date: Wed, 27 Apr 2022 17:42:43 GMT
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Type: application/json; charset=utf-8
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Result JSON: {"keyChange":"https://localhost:14000/rollover-account-key","meta":{"externalAccountRequired":false,"termsOfService":"data:text/plain,Do%20what%20thou%20wilt"},"newAccount":"https://localhost:14000/sign-me-up","newNonce":"https://localhost:14000/nonce-plz","newOrder":"https://localhost:14000/order-plz","revokeCert":"https://localhost:14000/revoke-cert"}
```

You can see that a `GET` request to the directory `https://localhost:14000/dir` was sent, and you see the `HEADER`s that were returned by the server, and the `Result JSON` that was found in the response body.

If _acme4j_ has no current nonce, it will fetch a new one from the `newNonce` endpoint found in the directory. A `HEAD` request is sufficient for that.

```text
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEAD https://localhost:14000/nonce-plz
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Cache-Control: public, max-age=0, no-cache
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Replay-Nonce: Os_sBjfWzVZenwwjvLrwXA
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Date: Wed, 27 Apr 2022 17:42:43 GMT
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Link: <https://localhost:14000/dir>;rel="index"
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Replay Nonce: Os_sBjfWzVZenwwjvLrwXA
```

In the bottom line, the `Replay Nonce` is repeated that was found in the response header.

Now _acme4j_ sends a `POST` request to the `newAccount` endpoint. As `Payload`, it will consent to the terms of service, and give optional account information (like the account e-mail address if given). You can also see the `JWS Header` that was sent with the request. It contains the target URL, the *public* JWK of your new account, the nonce from above, and the key algorithm.

```text
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils - POST https://localhost:14000/sign-me-up
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils -   Payload: {"termsOfServiceAgreed":true}
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils -   JWS Header: {"url":"https://localhost:14000/sign-me-up","jwk":{"kty":"RSA","n":"jyTwiSJACtW_SW-aiihQS5Y5QR704zUwjhlevY0oK-y5wP7SlIc2hq2OPVRarCzjhOxZl2AQFzM5VCR7xRDcnIn9t_pl7Mgsnx9hKDS9yQ24YXzhQ4cMEVVuqwcHvXqPdWDSoCZ1ccMqiiPyBSNGQTXMPY5PBxMOR47XwOb4eNMOPqnzVio3MEtL2wphtEonP3MY6pxJJzzel04wSCRZ4n06reqwER3KwRFPnRpRxAgmSEot5IBLIT3jj-amT5sD7YoUDbPmLk23zgDBIhX88fkClilg1W-fUi1XxYZomEPGvV7OrE1yszt4YDPqKgjJT8t2JPy__1ri-8rZgSxn5Q","e":"AQAB"},"nonce":"Os_sBjfWzVZenwwjvLrwXA","alg":"RS256"}
```

This is a possible response of the server:

```text
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Cache-Control: public, max-age=0, no-cache
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Replay-Nonce: mmnKF6lBuisPWhj9kkFMRA
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Length: 491
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Date: Wed, 27 Apr 2022 17:42:43 GMT
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Link: <https://localhost:14000/dir>;rel="index"
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Location: https://localhost:14000/my-account/1
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Type: application/json; charset=utf-8
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Replay Nonce: mmnKF6lBuisPWhj9kkFMRA
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Location: https://localhost:14000/my-account/1
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Result JSON: {"status":"valid","orders":"https://localhost:14000/list-orderz/1","key":{"kty":"RSA","n":"jyTwiSJACtW_SW-aiihQS5Y5QR704zUwjhlevY0oK-y5wP7SlIc2hq2OPVRarCzjhOxZl2AQFzM5VCR7xRDcnIn9t_pl7Mgsnx9hKDS9yQ24YXzhQ4cMEVVuqwcHvXqPdWDSoCZ1ccMqiiPyBSNGQTXMPY5PBxMOR47XwOb4eNMOPqnzVio3MEtL2wphtEonP3MY6pxJJzzel04wSCRZ4n06reqwER3KwRFPnRpRxAgmSEot5IBLIT3jj-amT5sD7YoUDbPmLk23zgDBIhX88fkClilg1W-fUi1XxYZomEPGvV7OrE1yszt4YDPqKgjJT8t2JPy__1ri-8rZgSxn5Q","e":"AQAB"}}
```

In the `HEADER` section, you can find a new replay nonce and the location of your new account. This information is repeated in the `Replay Nonce` and `Location` lines. You can also read the response body as `Result JSON`. It contains the account `status`, further links (e.g. for ordering), and other information.

## Example Error Log Output

Errors are usually sent as JSON problem structure. In the next example we have tried to create a new account, but used a bad nonce.

Again, we see the `POST` request to the `newAccount` endpoint. It uses the nonce `I6rXikEqxJ0aRwu1RvspNw` in the `JWS Header`. That nonce might have already been used in a previous request and is invalid now.

```text
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils - POST https://localhost:14000/sign-me-up
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils -   Payload: {"contact":["mailto:acme@example.com"],"termsOfServiceAgreed":true}
[main] DEBUG org.shredzone.acme4j.toolbox.JoseUtils -   JWS Header: {"url":"https://localhost:14000/sign-me-up","jwk":{"kty":"RSA","n":"y5i_8yG9IlL8ra2UWSK12Zy-dS0BYFvu2lerAoJQmYBwtPreOXu4OoIU6ZySAsMxlu2gMLaib62DFAFckEwQP4Bu8yJ4MWdSsiPu6pEs0SAvC61e3lYyDPbSG7FMykhWg5pjbK_NJ4Ysk64DrSA4kc0vxo54YKgxZfzObr4CHBZDaJmkTVtRndI7a8mNFO9pDlfHyb3UyZZPsg3kAUbnI9n3pZatdlGrv6eonbNAREjLvplGEI0_8B08S5fDcm6MqNarxNQIXlEhGDNoYLMGi5tM6CzsfXosHz42Umcym0EXvT1VjfoZMacSDsXleSRwjgewz486LDMErZSc0aUPSQ","e":"AQAB"},"nonce":"I6rXikEqxJ0aRwu1RvspNw","alg":"RS256"}
```

The server responds with a `400 Bad Request` and an `application/problem+json` document:

```text
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Cache-Control: public, max-age=0, no-cache
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Replay-Nonce: LDDZAGcBuKYpuNlFTCxPYw
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Length: 147
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Date: Wed, 27 Apr 2022 17:42:43 GMT
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Link: <https://localhost:14000/dir>;rel="index"
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - HEADER Content-Type: application/problem+json; charset=utf-8
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Replay Nonce: LDDZAGcBuKYpuNlFTCxPYw
[main] DEBUG org.shredzone.acme4j.connector.DefaultConnection - Result JSON: {"type":"urn:ietf:params:acme:error:badNonce","detail":"JWS has an invalid anti-replay nonce: I6rXikEqxJ0aRwu1RvspNw","status":400}
```

In the `Result JSON`, you can see a JSON problem document. The `type` and `detail` fields gives further information about the error.

Fortunately, bad nonces are handled by _acme4j_ internally. It will just resend the request with a new nonce.

```text
[main] INFO org.shredzone.acme4j.connector.DefaultConnection - Bad Replay Nonce, trying again (attempt 1/10)
```
