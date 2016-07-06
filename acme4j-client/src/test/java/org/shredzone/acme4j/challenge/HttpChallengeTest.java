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
import java.net.InetAddress;

import org.junit.BeforeClass;
import org.junit.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Http01Challenge}.
 *
 * @author Richard "Shred" Körber
 */
public class HttpChallengeTest {
    private static final String TOKEN =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ";
    private static final String KEY_AUTHORIZATION =
            "rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    private static Session session;

    @BeforeClass
    public static void setup() throws IOException {
        session = TestUtils.session();
    }

    /**
     * Test that {@link Http01Challenge} generates a correct authorization key.
     */
    @Test
    public void testHttpChallenge() throws IOException {
        Http01Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("httpChallenge"));

        assertThat(challenge.getType(), is(Http01Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getToken(), is(TOKEN));
        assertThat(challenge.getAuthorization(), is(KEY_AUTHORIZATION));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\"}").allowingExtraUnexpectedFields());
    }

    /**
     * Test that {@link Http01Challenge} uses the given address.
     */
    @Test
    public void testAddress() throws IOException {
        Http01Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("httpChallenge"));

        challenge.setAddress(InetAddress.getByName("198.051.100.012"));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\", \"address\"=\"198.51.100.12\"}")
                        .allowingExtraUnexpectedFields());
    }

}
