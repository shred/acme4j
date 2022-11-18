/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.wrapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

import jakarta.mail.Header;
import jakarta.mail.internet.InternetAddress;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;

/**
 * Unit tests for {@link SignedMail}.
 */
public class SignedMailTest {

    @Test
    public void testCheckDuplicatedStrictGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com"
        ));

        // Success: Field is present and identical
        signedMail.checkDuplicatedField("From", "foo@example.com", false);

        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testCheckDuplicatedStrictBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "  foo@example.com "
        ));

        // Failure: Field is same, but has extra whitespaces
        assertThatExceptionOfType(AcmeInvalidMessageException.class).isThrownBy(() ->
                signedMail.checkDuplicatedField("From", "foo@example.com", false)
        );
    }

    @Test
    public void testCheckDuplicatedRelaxedGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "FROM", "  foo@example.com "
        ));

        // Good: Field is there and identical (ignoring case and whitespaces)
        signedMail.checkDuplicatedField("From", "foo@example.com", true);

        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testCheckDuplicatedRelaxedBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "bar@example.com"
        ));

        // Failure: Field is present, but different value
        assertThatExceptionOfType(AcmeInvalidMessageException.class).isThrownBy(() ->
                signedMail.checkDuplicatedField("From", "foo@example.com", true)
        );
    }

    @Test
    public void testDeleteFieldStrictGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com"
        ));

        // Good: Field is present and identical
        signedMail.deleteField("From", "foo@example.com", false);

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getFrom)
                .withMessage("Protected 'FROM' header is required, but missing");
    }

    @Test
    public void testDeleteFieldStrictBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "bar@example.com"
        ));

        // Bad: Field is present, but has different value
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> signedMail.deleteField("From", "foo@example.com", false))
                .withMessage("Secured header 'From' was not found in envelope header for deletion");
    }

    @Test
    public void testDeleteFieldRelaxedGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "FROM", "   foo@example.com "
        ));

        // Good: Field is present and identical (ignoring case and whitespaces)
        signedMail.deleteField("From", "foo@example.com", true);

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getFrom)
                .withMessage("Protected 'FROM' header is required, but missing");
    }

    @Test
    public void testDeleteFieldRelaxedBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "FROM", "bar@example.com"
        ));

        // Bad: Field is present, but has different value
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> signedMail.deleteField("From", "foo@example.com", true))
                .withMessage("Secured header 'From' was not found in envelope header for deletion");
    }

    @Test
    public void testModifyFieldStrictGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com"
        ));

        // Good: field is present, content is replaced
        signedMail.modifyField("From", "bar@example.com", false);

        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("bar@example.com"));
    }

    @Test
    public void testModifyFieldStrictBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "FROM", "foo@example.com"
        ));

        // Failure: Field is not present because it's all-caps
        assertThatExceptionOfType(AcmeInvalidMessageException.class).isThrownBy(() ->
                signedMail.modifyField("From", "bar@example.com", false)
        );
    }

    @Test
    public void testModifyFieldRelaxedGood() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "FROM", "foo@example.com"
        ));

        // Good: Field is present (ignoring case)
        signedMail.modifyField("From", "bar@example.com", true);

        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("bar@example.com"));
    }

    @Test
    public void testModifyFieldRelaxedBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "To", "foo@example.com"
        ));

        // Failure: Field is not present at all
        assertThatExceptionOfType(AcmeInvalidMessageException.class).isThrownBy(() ->
                signedMail.modifyField("From", "foo@example.com", true)
        );
    }

    @Test
    public void testImportUntrusted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com",
                "Message-Id", "123456ABCDEF"
        ));

        // Success because Message ID does not need to be trusted
        assertThat(signedMail.getMessageId()).isNotEmpty().contains("123456ABCDEF");

        // Failure because From is required to be trusted
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getFrom);
    }

    @Test
    public void testImportTrustedStrict() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com",
                "Message-Id", "123456ABCDEF"
        ));
        signedMail.importTrustedHeaders(withHeaders(
                "From", "foo@example.com"
        ));

        // Success because Message ID does not need to be trusted
        assertThat(signedMail.getMessageId()).isNotEmpty().contains("123456ABCDEF");

        // Success because From is trusted
        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testImportTrustedRelaxed() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Message-Id", "123456ABCDEF"
        ));
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "From", "foo@example.com"
        ));

        // Success because Message ID does not need to be trusted
        assertThat(signedMail.getMessageId()).isNotEmpty().contains("123456ABCDEF");

        // Success because From is trusted
        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testImportStrictFails() {
        var signedMail = new SignedMail();

        // Fails because there is no matching untrusted header
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(() -> signedMail.importTrustedHeaders(withHeaders(
                        "From", "foo@example.com"
                )));
    }

    @Test
    public void testFromEmpty() {
        var signedMail = new SignedMail();
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getFrom)
                .withMessage("Protected 'FROM' header is required, but missing");
    }

    @Test
    public void testFromUntrusted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com"
        ));

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getFrom)
                .withMessage("Protected 'FROM' header is required, but missing");
    }

    @Test
    public void testFromTrusted() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "From", "foo@example.com"
        ));

        assertThat(signedMail.getFrom()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testToEmpty() {
        var signedMail = new SignedMail();
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getTo)
                .withMessage("Protected 'TO' header is required, but missing");
    }

    @Test
    public void testToUntrusted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "To", "foo@example.com"
        ));

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getTo)
                .withMessage("Protected 'TO' header is required, but missing");
    }

    @Test
    public void testToTrusted() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "To", "foo@example.com"
        ));

        assertThat(signedMail.getTo()).isEqualTo(new InternetAddress("foo@example.com"));
    }

    @Test
    public void testSubjectEmpty() {
        var signedMail = new SignedMail();
        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getSubject)
                .withMessage("Protected 'SUBJECT' header is required, but missing");
    }

    @Test
    public void testSubjectUntrusted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Subject", "abc123"
        ));

        assertThatExceptionOfType(AcmeInvalidMessageException.class)
                .isThrownBy(signedMail::getSubject)
                .withMessage("Protected 'SUBJECT' header is required, but missing");
    }

    @Test
    public void testSubjectTrusted() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "Subject", "abc123"
        ));

        assertThat(signedMail.getSubject()).isEqualTo("abc123");
    }

    @Test
    public void testMessageIdEmpty() {
        var signedMail = new SignedMail();
        assertThat(signedMail.getMessageId()).isEmpty();
    }

    @Test
    public void testMessageId() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Message-Id", "12345ABCDE"
        ));

        assertThat(signedMail.getMessageId()).isNotEmpty().contains("12345ABCDE");
    }

    @Test
    public void testReplyToEmpty() throws Exception {
        var signedMail = new SignedMail();
        assertThat(signedMail.getReplyTo()).isEmpty();
    }

    @Test
    public void testReplyTo() throws Exception {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Reply-To", "foo@example.com",
                "Reply-To", "bar@example.org"
        ));

        assertThat(signedMail.getReplyTo()).contains(
                new InternetAddress("foo@example.com"),
                new InternetAddress("bar@example.org")
        );
    }

    @Test
    public void testIsAutoSubmitted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Auto-Submitted", "auto-generated; type=acme"
        ));

        assertThat(signedMail.isAutoSubmitted()).isTrue();
    }

    @Test
    public void testIsNotAutoSubmitted() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "Auto-Submitted", "no"
        ));

        assertThat(signedMail.isAutoSubmitted()).isFalse();
    }

    @Test
    public void testIsAutoSubmittedMissing() {
        var signedMail = new SignedMail();
        assertThat(signedMail.isAutoSubmitted()).isFalse();
    }

    @Test
    public void testMissingSecuredHeadersEmpty() {
        var signedMail = new SignedMail();
        assertThat(signedMail.getMissingSecuredHeaders()).contains("FROM", "TO", "SUBJECT");
    }

    @Test
    public void testMissingSecuredHeadersGood() {
        var signedMail = new SignedMail();
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "From", "foo@example.com",
                "To", "bar@example.org",
                "Subject", "foo123"
        ));

        assertThat(signedMail.getMissingSecuredHeaders()).isEmpty();
    }

    @Test
    public void testMissingSecuredHeadersTrustedBad() {
        var signedMail = new SignedMail();
        signedMail.importTrustedHeadersRelaxed(withHeaders(
                "From", "foo@example.com",
                "To", "bar@example.org"
        ));

        assertThat(signedMail.getMissingSecuredHeaders()).contains("SUBJECT");
    }

    @Test
    public void testMissingSecuredHeadersUntustedBad() {
        var signedMail = new SignedMail();
        signedMail.importUntrustedHeaders(withHeaders(
                "From", "foo@example.com",
                "To", "bar@example.org",
                "Subject", "foo123"
        ));

        assertThat(signedMail.getMissingSecuredHeaders()).contains("FROM", "TO", "SUBJECT");
    }

    private Enumeration<Header> withHeaders(String... kv) {
        var headers = new ArrayList<Header>();
        for (var ix = 0; ix < kv.length; ix += 2) {
            headers.add(new Header(kv[ix], kv[ix+1]));
        }
        return Collections.enumeration(headers);
    }

}