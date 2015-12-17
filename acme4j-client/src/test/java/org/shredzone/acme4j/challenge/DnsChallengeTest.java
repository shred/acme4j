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
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.challenge.Challenge.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link DnsChallenge}.
 *
 * @author Richard "Shred" Körber
 */
public class DnsChallengeTest {

    private static final String TOKEN =
            "pNvmJivs0WCko2suV7fhe-59oFqyYx_yB7tx6kIMAyE";
    private static final String KEY_AUTHORIZATION =
            "pNvmJivs0WCko2suV7fhe-59oFqyYx_yB7tx6kIMAyE.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    /**
     * Test that {@link DnsChallenge} generates a correct authorization key.
     */
    @Test
    public void testHttpChallenge() throws IOException {
        KeyPair keypair = TestUtils.createKeyPair();
        Account account = new Account(keypair);

        DnsChallenge challenge = new DnsChallenge();
        challenge.unmarshall(TestUtils.getJsonAsMap("dnsChallenge"));

        assertThat(challenge.getType(), is(DnsChallenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));

        try {
            challenge.getAuthorization();
            fail("getAuthorization() without previous authorize()");
        } catch (IllegalStateException ex) {
            // expected
        }

        challenge.authorize(account);

        assertThat(challenge.getToken(), is(TOKEN));
        assertThat(challenge.getAuthorization(), is(KEY_AUTHORIZATION));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.marshall(cb);

        assertThat(cb.toString(), sameJSONAs("{\"keyAuthorization\"=\""
            + KEY_AUTHORIZATION + "\"}").allowingExtraUnexpectedFields());
    }

}
