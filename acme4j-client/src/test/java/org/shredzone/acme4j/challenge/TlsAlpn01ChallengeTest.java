/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link TlsAlpn01ChallengeTest}.
 */
public class TlsAlpn01ChallengeTest {
    private static final String TOKEN =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ";
    private static final String KEY_AUTHORIZATION =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    private final Login login = TestUtils.login();

    /**
     * Test that {@link TlsAlpn01Challenge} generates a correct authorization key.
     */
    @Test
    public void testTlsAlpn01Challenge() {
        var challenge = new TlsAlpn01Challenge(login, getJSON("tlsAlpnChallenge"));

        assertThat(challenge.getType()).isEqualTo(TlsAlpn01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getToken()).isEqualTo(TOKEN);
        assertThat(challenge.getAuthorization()).isEqualTo(KEY_AUTHORIZATION);
        assertThat(challenge.getAcmeValidation()).isEqualTo(AcmeUtils.sha256hash(KEY_AUTHORIZATION));

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

}
