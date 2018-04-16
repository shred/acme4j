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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;

import org.junit.Test;
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

    private Login login = TestUtils.login();

    /**
     * Test that {@link TlsAlpn01Challenge} generates a correct authorization key.
     */
    @Test
    public void testTlsAlpn01Challenge() throws IOException {
        TlsAlpn01Challenge challenge = new TlsAlpn01Challenge(login, getJSON("tlsAlpnChallenge"));

        assertThat(challenge.getType(), is(TlsAlpn01Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getToken(), is(TOKEN));
        assertThat(challenge.getAuthorization(), is(KEY_AUTHORIZATION));
        assertThat(challenge.getAcmeValidationV1(), is(AcmeUtils.sha256hash(KEY_AUTHORIZATION)));

        JSONBuilder response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThat(response.toString(), sameJSONAs("{}").allowingExtraUnexpectedFields());
    }

}
