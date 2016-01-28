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
import static org.junit.Assert.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.security.KeyPair;

import org.junit.Test;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link TlsSniChallenge}.
 *
 * @author Richard "Shred" Körber
 */
public class TlsSniChallengeTest {

    private static final String KEY_AUTHORIZATION =
            "VNLBdSiZ3LppU2CRG8bilqlwq4DuApJMg3ZJowU6JhQ.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    /**
     * Test that {@link TlsSniChallenge} generates a correct authorization key.
     */
    @Test
    public void testTlsSniChallenge() throws IOException {
        KeyPair keypair = TestUtils.createKeyPair();
        Registration reg = new Registration(keypair);

        TlsSniChallenge challenge = new TlsSniChallenge();
        challenge.unmarshall(TestUtils.getJsonAsMap("tlsSniChallenge"));

        assertThat(challenge.getType(), is(TlsSniChallenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));

        try {
            challenge.getSubject();
            fail("getSubject() without previous authorize()");
        } catch (IllegalStateException ex) {
            // expected
        }

        challenge.authorize(reg);

        assertThat(challenge.getSubject(), is("14e2350a04434f93c2e0b6012968d99d.ed459b6a7a019d9695609b8514f9d63d.acme.invalid"));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\"}").allowingExtraUnexpectedFields());
    }

}
