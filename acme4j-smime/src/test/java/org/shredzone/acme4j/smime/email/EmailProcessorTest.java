/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.email;

import static jakarta.mail.Message.RecipientType.TO;
import static org.assertj.core.api.Assertions.*;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Optional;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.smime.EmailIdentifier;
import org.shredzone.acme4j.smime.SMIMETests;
import org.shredzone.acme4j.smime.challenge.EmailReply00Challenge;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;

/**
 * Unit tests for {@link EmailProcessor} and {@link ResponseGenerator}.
 */
public class EmailProcessorTest extends SMIMETests {

    private final InternetAddress expectedFrom = email("acme-generator@example.org");
    private final InternetAddress expectedTo = email("alexey@example.com");
    private final InternetAddress expectedReplyTo = email("acme-validator@example.org");
    private final Message message = mockMessage("challenge");

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEmailParser() throws AcmeInvalidMessageException {
        EmailProcessor processor = EmailProcessor.plainMessage(message);
        processor.expectedFrom(expectedFrom);
        processor.expectedTo(expectedTo);
        processor.expectedIdentifier(EmailIdentifier.email(expectedTo));
        processor.expectedIdentifier(new Identifier("email", expectedTo.getAddress()));

        assertThat(processor.getSender()).isEqualTo(expectedFrom);
        assertThat(processor.getRecipient()).isEqualTo(expectedTo);
        assertThat(processor.getMessageId()).isEqualTo(Optional.of("<A2299BB.FF7788@example.org>"));
        assertThat(processor.getToken1()).isEqualTo(TOKEN_PART1);
        assertThat(processor.getReplyTo()).contains(email("acme-validator@example.org"));
    }

    @Test
    public void testValidSignature() {
        assertThatNoException().isThrownBy(() -> {
            MimeMessage message = mockMessage("valid-mail");
            X509Certificate certificate = readCertificate("valid-signer");
            EmailProcessor.builder().certificate(certificate).strict().build(message);
        });
    }

    @Test
    public void testInvalidSignature() {
        AcmeInvalidMessageException ex = catchThrowableOfType(() -> {
                    MimeMessage message = mockMessage("invalid-signed-mail");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                }, AcmeInvalidMessageException.class);

        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Invalid signature");
        assertThat(ex.getErrors()).hasSize(2);
        assertThat(ex.getErrors())
                .first().hasFieldOrPropertyWithValue("id", "SignedMailValidator.emailFromCertMismatch");
        assertThat(ex.getErrors())
                .element(1).hasFieldOrPropertyWithValue("id", "SignedMailValidator.certPathInvalid");
    }

    @Test
    public void testValidSignatureButNoSAN() {
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> {
                    MimeMessage message = mockMessage("invalid-nosan");
                    X509Certificate certificate = readCertificate("valid-signer-nosan");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                })
                .withMessage("Certificate does not have a subjectAltName extension");
    }

    @Test
    public void testSANDoesNotMatchFrom() {
        AcmeInvalidMessageException ex = catchThrowableOfType(() -> {
                    MimeMessage message = mockMessage("invalid-cert-mismatch");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                }, AcmeInvalidMessageException.class);

        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Invalid signature");
        assertThat(ex.getErrors())
                .singleElement().hasFieldOrPropertyWithValue("id", "SignedMailValidator.emailFromCertMismatch");
    }

    @Test
    public void testInvalidProtectedFromHeader() {
        AcmeInvalidMessageException ex = catchThrowableOfType(() -> {
                    MimeMessage message = mockMessage("invalid-protected-mail-from");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                }, AcmeInvalidMessageException.class);

        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Invalid signature");
        assertThat(ex.getErrors())
                .singleElement().hasFieldOrPropertyWithValue("id", "SignedMailValidator.emailFromCertMismatch");
    }

    @Test
    public void testInvalidProtectedToHeader() {
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> {
                    MimeMessage message = mockMessage("invalid-protected-mail-to");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                })
                .withMessage("Secured header 'To' does not match envelope header");
    }

    @Test
    public void testInvalidProtectedSubjectHeader() {
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> {
                    MimeMessage message = mockMessage("invalid-protected-mail-subject");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).strict().build(message);
                })
                .withMessage("Secured header 'Subject' does not match envelope header");
    }

    @Test
    public void testNonStrictInvalidProtectedSubjectHeader() {
        assertThatNoException()
                .isThrownBy(() -> {
                    MimeMessage message = mockMessage("invalid-protected-mail-subject");
                    X509Certificate certificate = readCertificate("valid-signer");
                    EmailProcessor.builder().certificate(certificate).relaxed().build(message);
                });
    }

    // TODO: This test is blocking development atm. It fails because the signature of
    // the test email has expired. In order to fix it, RFC-7508 compliant test emails
    // need to be generated programmatically within the unit test.
    @Disabled
    @Test
    public void testValidSignatureRfc7508() throws Exception {
        MimeMessage message = mockMessage("valid-mail-7508");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(EmailProcessorTest.class.getResourceAsStream("/7508-valid-ca.jks"), "test123".toCharArray());

        EmailProcessor processor = EmailProcessor.builder().trustStore(keyStore).build(message);
        assertThat(processor.getSender()).isEqualTo(new InternetAddress("acme-challenge@dc-bsd.my.corp"));
        assertThat(processor.getRecipient()).isEqualTo(new InternetAddress("gitlab@dc-bsd.my.corp"));
        assertThat(processor.getToken1()).isEqualTo("ABxfL5s4bjvmyVRvl6y-Y_GhdzTdWpKqlmrKAIVe");
    }

    // TODO: This test is blocking development atm. It fails because the keystore format
    // is invalid. This might be fixed together with testValidSignatureRfc7508().
    @Disabled
    @Test
    public void testInvalidSignatureRfc7508() throws Exception {
        MimeMessage message = mockMessage("valid-mail-7508");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(EmailProcessorTest.class.getResourceAsStream("/7508-fake-ca.jks"), "test123".toCharArray());

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> EmailProcessor.builder().trustStore(keyStore).build(message));
    }

    @Test
    public void textExpectedFromFails() {
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.expectedFrom(expectedTo);
                })
                .withMessage("Message is not sent by the expected sender");
    }

    @Test
    public void textExpectedToFails() {
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.expectedTo(expectedFrom);
                })
                .withMessage("Message is not addressed to expected recipient");
    }

    @Test
    public void textExpectedIdentifierFails1() {
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.expectedIdentifier(EmailIdentifier.email(expectedFrom));
                })
                .withMessage("Message is not addressed to expected recipient");
    }

    @Test
    public void textExpectedIdentifierFails2() {
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.expectedIdentifier(Identifier.ip("192.168.0.1"));
                })
                .withMessage("Wrong identifier type: ip");
    }

    @Test
    public void textNoChallengeFails1() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.getToken();
                })
                .withMessage("No challenge has been set yet");
    }

    @Test
    public void textNoChallengeFails2() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.getAuthorization();
                })
                .withMessage("No challenge has been set yet");
    }

    @Test
    public void textNoChallengeFails3() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> {
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.respond();
                })
                .withMessage("No challenge has been set yet");
    }

    @Test
    public void testChallenge() throws AcmeInvalidMessageException {
        EmailReply00Challenge challenge = mockChallenge("emailReplyChallenge");

        EmailProcessor processor = EmailProcessor.plainMessage(message);
        processor.withChallenge(challenge);
        assertThat(processor.getToken()).isEqualTo(TOKEN);
        assertThat(processor.getAuthorization()).isEqualTo(KEY_AUTHORIZATION);
        assertThat(processor.respond()).isNotNull();
    }

    @Test
    public void testChallengeMismatch() {
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> {
                    EmailReply00Challenge challenge = mockChallenge("emailReplyChallengeMismatch");
                    EmailProcessor processor = EmailProcessor.plainMessage(message);
                    processor.withChallenge(challenge);
                })
                .withMessage("Message is not sent by the expected sender");
    }

    @Test
    public void testResponse() throws IOException, MessagingException, AcmeInvalidMessageException {
        EmailReply00Challenge challenge = mockChallenge("emailReplyChallenge");

        Message response = EmailProcessor.plainMessage(message)
                .withChallenge(challenge)
                .respond()
                .generateResponse(mailSession);

        assertResponse(response, RESPONSE_BODY);
    }

    @Test
    public void testResponseWithHeaderFooter() throws IOException, MessagingException, AcmeInvalidMessageException {
        EmailReply00Challenge challenge = mockChallenge("emailReplyChallenge");

        Message response = EmailProcessor.plainMessage(message)
                .withChallenge(challenge)
                .respond()
                .withHeader("This is an introduction.")
                .withFooter("This is a footer.")
                .generateResponse(mailSession);

        assertResponse(response,
                "This is an introduction.\r\n"
                + RESPONSE_BODY
                + "This is a footer.");
    }

    @Test
    public void testResponseWithCallback() throws IOException, MessagingException, AcmeInvalidMessageException {
        EmailReply00Challenge challenge = mockChallenge("emailReplyChallenge");

        Message response = EmailProcessor.plainMessage(message)
                .withChallenge(challenge)
                .respond()
                .withGenerator((msg, body) -> msg.setContent("Head\r\n" + body + "Foot", "text/plain"))
                .generateResponse(mailSession);

        assertResponse(response, "Head\r\n" + RESPONSE_BODY + "Foot");
    }

    private void assertResponse(Message response, String expectedBody)
            throws MessagingException, IOException {
        assertThat(response.getContentType()).isEqualTo("text/plain");
        assertThat(response.getContent().toString()).isEqualTo(expectedBody);

        // This is a response, so the expected sender is the recipient of the challenge
        assertThat(response.getFrom()).hasSize(1);
        assertThat(response.getFrom()[0]).isEqualTo(expectedTo);

        // There is a Reply-To header, so we expect the mail to go only there
        assertThat(response.getRecipients(TO)).hasSize(1);
        assertThat(response.getRecipients(TO)[0]).isEqualTo(expectedReplyTo);

        assertThat(response.getSubject()).isEqualTo("Re: ACME: " + TOKEN_PART1);

        String[] inReplyToHeader = response.getHeader("In-Reply-To");
        assertThat(inReplyToHeader).hasSize(1);
        assertThat(inReplyToHeader[0]).isEqualTo("<A2299BB.FF7788@example.org>");
    }

}
