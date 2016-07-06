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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Dns01Challenge}.
 *
 * @author Richard "Shred" Körber
 */
public class DnsChallengeTest {
    private static final String KEY_AUTHORIZATION =
            "pNvmJivs0WCko2suV7fhe-59oFqyYx_yB7tx6kIMAyE.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    private static Session session;

    @BeforeClass
    public static void setup() throws IOException {
        session = TestUtils.session();
    }

    /**
     * Test that {@link Dns01Challenge} generates a correct authorization key.
     */
    @Test
    public void testDnsChallenge() throws IOException {
        Dns01Challenge challenge = new Dns01Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("dnsChallenge"));

        assertThat(challenge.getType(), is(Dns01Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getDigest(), is("rzMmotrIgsithyBYc0vgiLUEEKYx0WetQRgEF2JIozA"));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\"}").allowingExtraUnexpectedFields());
    }

}
