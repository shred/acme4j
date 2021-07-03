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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import java.net.URI;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;
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
        AcmeProvider provider = new TestAcmeProvider();

        Challenge challenge = provider.createChallenge(mockLogin(), getJSON("emailReplyChallenge"));
        assertThat(challenge, not(nullValue()));
        assertThat(challenge, instanceOf(EmailReply00Challenge.class));
    }

    /**
     * Test that {@link EmailReply00Challenge} generates a correct authorization key.
     */
    @Test
    public void testEmailReplyChallenge() {
        EmailReply00Challenge challenge = new EmailReply00Challenge(mockLogin(), getJSON("emailReplyChallenge"));

        assertThat(challenge.getType(), is(EmailReply00Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getToken(TOKEN_PART1), is(TOKEN_PART1 + TOKEN_PART2));
        assertThat(challenge.getTokenPart2(), is(TOKEN_PART2));
        assertThat(challenge.getAuthorization(TOKEN_PART1), is(KEY_AUTHORIZATION));

        assertThat(challenge.getFrom(), is("acme-generator@example.org"));
        assertThat(challenge.getExpectedSender().getAddress(), is("acme-generator@example.org"));
    }

    /**
     * Test that {@link EmailReply00Challenge#getAuthorization()} is not implemented.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testInvalidGetAuthorization() {
        EmailReply00Challenge challenge = new EmailReply00Challenge(mockLogin(), getJSON("emailReplyChallenge"));
        challenge.getAuthorization();
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
