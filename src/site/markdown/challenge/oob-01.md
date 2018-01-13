# oob-01 Challenge

> **NOTE:** `oob-01` challenge has been removed in ACMEv2.

The `oob-01` challenge is an "out of band" challenge that is used when there is no automatic way of validating ownership of a domain. The client is instead required to perform actions outside of the ACME protocol.

`OutOfBand01Challenge` implements this challenge. Its `getValidationUrl()` method returns a URL that refers to a web page with further instructions about the actions to be taken.

The challenge must be triggered before the URL is opened in a browser.

Due to the nature of this challenge, it may take a considerable amount of time until its state changes to `VALID`.
