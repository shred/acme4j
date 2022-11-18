/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.challenge;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Http01Challenge}.
 */
public class HttpChallengeTest {
    private static final String TOKEN =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ";
    private static final String KEY_AUTHORIZATION =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    private final Login login = TestUtils.login();

    /**
     * Test that {@link Http01Challenge} generates a correct authorization key.
     */
    @Test
    public void testHttpChallenge() {
        var challenge = new Http01Challenge(login, getJSON("httpChallenge"));

        assertThat(challenge.getType()).isEqualTo(Http01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getToken()).isEqualTo(TOKEN);
        assertThat(challenge.getAuthorization()).isEqualTo(KEY_AUTHORIZATION);

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

    /**
     * Test that an exception is thrown if there is no token.
     */
    @Test
    public void testNoTokenSet() {
        assertThrows(AcmeProtocolException.class, () -> {
            Http01Challenge challenge = new Http01Challenge(login, getJSON("httpNoTokenChallenge"));
            challenge.getToken();
        });
    }

}
