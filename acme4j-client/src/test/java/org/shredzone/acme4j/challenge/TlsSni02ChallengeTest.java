/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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
 * Unit tests for {@link TlsSni02Challenge}.
 *
 * @author Richard "Shred" Körber
 */
public class TlsSni02ChallengeTest {
    private static final String KEY_AUTHORIZATION =
            "VNLBdSiZ3LppU2CRG8bilqlwq4DuApJMg3ZJowU6JhQ.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    private static Session session;

    @BeforeClass
    public static void setup() throws IOException {
        session = TestUtils.session();
    }

    /**
     * Test that {@link TlsSni02Challenge} generates a correct authorization key.
     */
    @Test
    public void testTlsSni02Challenge() throws IOException {
        TlsSni02Challenge challenge = new TlsSni02Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("tlsSni02Challenge"));

        assertThat(challenge.getType(), is(TlsSni02Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getSubject(), is("5bf0b9908ed73bc53ed3327afa52f76b.0a4bea00520f0753f42abe0bb39e3ea8.token.acme.invalid"));
        assertThat(challenge.getSanB(), is("14e2350a04434f93c2e0b6012968d99d.ed459b6a7a019d9695609b8514f9d63d.ka.acme.invalid"));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\"}").allowingExtraUnexpectedFields());
    }

}
