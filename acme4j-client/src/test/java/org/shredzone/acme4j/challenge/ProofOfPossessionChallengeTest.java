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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;
import org.shredzone.acme4j.util.ValidationBuilder;

/**
 * Unit tests for {@link ProofOfPossessionChallenge}.
 *
 * @author Richard "Shred" Körber
 */
public class ProofOfPossessionChallengeTest {

    /**
     * Test that {@link ProofOfPossessionChallenge} generates a correct authorization key.
     */
    @Test
    public void testProofOfPossessionChallenge() throws IOException {
        X509Certificate cert = TestUtils.createCertificate();
        KeyPair keypair = TestUtils.createKeyPair();
        Account account = new Account(keypair);
        KeyPair domainKeyPair = TestUtils.createDomainKeyPair();

        ProofOfPossessionChallenge challenge = new ProofOfPossessionChallenge();
        challenge.unmarshall(TestUtils.getJsonAsMap("proofOfPossessionChallenge"));

        assertThat(challenge.getCertificates(), contains(cert));

        assertThat(challenge.getType(), is(ProofOfPossessionChallenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.PENDING));

        try {
            challenge.respond(new ClaimBuilder());
            fail("marshall() without previous authorize()");
        } catch (IllegalStateException ex) {
            // expected
        }

        challenge.authorize(account, domainKeyPair, "example.org");

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"type\"=\""
            + ProofOfPossessionChallenge.TYPE + "\",\"authorization\"="
            + new ValidationBuilder().domain("example.org").sign(account, domainKeyPair)
            + "}"));
    }

    /**
     * Test that {@link ProofOfPossessionChallenge#importValidation(String)} works
     * correctly.
     */
    @Test
    public void testImportValidation() throws IOException {
        KeyPair keypair = TestUtils.createKeyPair();
        Account account = new Account(keypair);
        KeyPair domainKeyPair = TestUtils.createDomainKeyPair();

        String validation = new ValidationBuilder()
                .domain("example.org")
                .sign(account, domainKeyPair);

        ProofOfPossessionChallenge challenge = new ProofOfPossessionChallenge();
        challenge.unmarshall(TestUtils.getJsonAsMap("proofOfPossessionChallenge"));
        challenge.importValidation(validation);

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"type\"=\""
            + ProofOfPossessionChallenge.TYPE + "\",\"authorization\"=" + validation
            + "}"));
    }

}
