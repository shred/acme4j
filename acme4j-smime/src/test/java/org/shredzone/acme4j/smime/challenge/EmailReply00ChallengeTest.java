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
package org.shredzone.acme4j.smime.challenge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.net.URL;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.smime.SMIMETests;

/**
 * Unit tests for {@link EmailReply00Challenge}.
 */
public class EmailReply00ChallengeTest extends SMIMETests {

    /**
     * Test that the challenge provider is found and the challenge is generated properly.
     */
    @Test
    public void testCreateChallenge() {
        var provider = new TestAcmeProvider();

        var challenge = provider.createChallenge(mockLogin(), getJSON("emailReplyChallenge"));
        assertThat(challenge).isNotNull();
        assertThat(challenge).isInstanceOf(EmailReply00Challenge.class);
    }

    /**
     * Test that {@link EmailReply00Challenge} generates a correct authorization key.
     */
    @Test
    public void testEmailReplyChallenge() {
        var challenge = new EmailReply00Challenge(mockLogin(), getJSON("emailReplyChallenge"));

        assertThat(challenge.getType()).isEqualTo(EmailReply00Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getToken(TOKEN_PART1)).isEqualTo(TOKEN_PART1 + TOKEN_PART2);
        assertThat(challenge.getTokenPart2()).isEqualTo(TOKEN_PART2);
        assertThat(challenge.getAuthorization(TOKEN_PART1)).isEqualTo(KEY_AUTHORIZATION);

        assertThat(challenge.getFrom()).isEqualTo("acme-generator@example.org");
        assertThat(challenge.getExpectedSender().getAddress()).isEqualTo("acme-generator@example.org");
    }

    /**
     * Test that {@link EmailReply00Challenge#getAuthorization()} is not implemented.
     */
    @Test
    public void testInvalidGetAuthorization() {
        assertThrows(UnsupportedOperationException.class, () -> {
            var challenge = new EmailReply00Challenge(mockLogin(), getJSON("emailReplyChallenge"));
            challenge.getAuthorization();
        });
    }

    /**
     * A minimal {@link AbstractAcmeProvider} implementation for testing the challenge
     * builder.
     */
    private static class TestAcmeProvider extends AbstractAcmeProvider {
        @Override
        public boolean accepts(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public URL resolve(URI serverUri) {
            throw new UnsupportedOperationException();
        }
    }

}
