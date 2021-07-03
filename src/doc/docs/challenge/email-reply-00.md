# email-reply-00 Challenge

The `email-reply-00` challenge permits to get end-user S/MIME certificates, as specified in [RFC 8823](https://tools.ietf.org/html/rfc8823).

The CA must support issuance of S/MIME certificates. _Let's Encrypt_ does not currently support it.

!!! warning
    The support of this challenge is **experimental**. The implementation is only unit tested for compliance with the RFC, but is not integration tested yet. There may be breaking changes in this part of the API in future releases.

## Setup and Requirements

To use the S/MIME support, you need to:

* add the `acme4j-smime` module to your list of dependencies
* make sure that `BouncyCastleProvider` is added as security provider
* add a `javax.mail` implementation to your classpath (e.g. the [JavaMail Reference Implementation](https://javaee.github.io/javamail/))

[RFC 8823](https://tools.ietf.org/html/rfc8823) requires that the DKIM or S/MIME signature of incoming mails _must_ be checked. Outgoing mails _must_ have a valid DKIM or S/MIME signature. This is out of the scope of `acme4j-smime`, but is usually performed by a MTA.

## Ordering

The certificate ordering process is similar to a standard domain certificate order.

However, if `Identifier` objects are needed, use `EmailIdentifier.email()` to generate an identifier for the email address you want an S/MIME certificate for.

To generate a CSR, the module provides a `SMIMECSRBuilder` that works similar to the standard `CSRBuilder`, but accepts `EmailIdentifier` objects.

With the `SMIMECSRBuilder.setKeyUsageType()`, the desired usage type of the S/MIME certificate can be selected. By default the certificate can be used both for encryption and signing. However this is just a proposal, and the CA is free to ignore it or return an error if the desired usage type is not supported.

## Challenge and Response

The CA validates ownership of the email address by two components.

Firstly, the CA sends a challenge email to the email address that requested the S/MIME certificate. The subject of this email always starts with an `ACME:` prefix, so it can be filtered by the inbound MTA for automatic processing. After the prefix, the mail subject contains the first part of the challenge token (called "Token 1").

Secondly, the CA provides a new `EmailReply00Challenge` challenge that needs to be verified by the client. The challenge contains the second part of the challenge token (called "Token 2"). Both token parts are concatenated to give the full token that is required for generating the key authorization. The `EmailReply00Challenge` class offers methods like `getToken(String part1)`, `getTokenPart2()`, and `getAuthorization(String part1)` for that.

The client now needs to generate a response to the request email. This is a standard mail response to the sender's address. The subject line must be kept, except of an optional `Re:` or a similar prefix. The mail body must contain a `text/plain` part that contains the wrapped key authorization string. For example:

```text
-----BEGIN ACME RESPONSE-----
LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowy
jxAjEuX0=
-----END ACME RESPONSE-----
```

This response is sent back to the CA.

After that, the `EmailReply00Challenge` is triggered. The CA now has a proof of ownership of the email address, and can issue the S/MIME certificate.

## Response Helper

The response process can be executed programatically, or even manually. To help with the process, `acme4j-smime` provides an `EmailProcessor` that helps you parsing the challenge email, and generate a matching response mail.

It is basically invoked like this:

```java
Message               challengeMessage = // incoming challenge message from the CA
EmailReply00Challenge challenge        = // challenge that is requested by the CA
EmailIdentifier       identifier       = // email address to get the S/MIME cert for
javax.mail.Session    mailSession      = // javax.mail session

Message response = new EmailProcessor(challengeMessage)
            .expectedIdentifier(identifier)
            .withChallenge(challenge)
            .respond()
            .generateResponse(mailSession);

Transport.send(response);   // send response to the CA
challenge.trigger();        // trigger the challenge
```

The `EmailProcessor` and the related `ResponseGenerator` offer more methods for validating and for customizing the response email.
