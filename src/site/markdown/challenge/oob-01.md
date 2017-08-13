# oob-01 Challenge

The `oob-01` challenge is an "out of band" challenge that is used when there is no automatic way of validating ownership of a domain. The client is instead required to perform actions outside of the ACME protocol.

`OutOfBand01Challenge` implements this challenge. Its `getValidationUrl()` method returns a URL that refers to a web page with further instructions about the actions to be taken by the domain owner.

The challenge must be triggered _before_ the URL is presented to the domain owner.

> __Note:__ Due to the nature of this challenge, it may take hours or even days until the domain owner finishes the actions and the challenge state changes to `VALID`.
