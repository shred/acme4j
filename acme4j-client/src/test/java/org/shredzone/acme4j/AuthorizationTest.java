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
package org.shredzone.acme4j;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.DnsChallenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.challenge.ProofOfPossessionChallenge;
import org.shredzone.acme4j.challenge.TlsSniChallenge;

/**
 * Unit tests for {@link Authorization}.
 *
 * @author Richard "Shred" Körber
 */
public class AuthorizationTest {

    private Authorization authorization;

    /**
     * Sets up an {@link Authorization} to be tested.
     */
    @Before
    public void setup() {
        Challenge challenge1 = setupChallenge(HttpChallenge.TYPE, new HttpChallenge());
        Challenge challenge2 = setupChallenge(DnsChallenge.TYPE, new DnsChallenge());
        Challenge challenge3 = setupChallenge(TlsSniChallenge.TYPE, new TlsSniChallenge());

        List<Challenge> challenges = new ArrayList<>();
        challenges.add(challenge1);
        challenges.add(challenge2);
        challenges.add(challenge3);

        List<List<Challenge>> combinations = new ArrayList<>();
        combinations.add(Collections.unmodifiableList(Arrays.asList(challenge1)));
        combinations.add(Collections.unmodifiableList(Arrays.asList(challenge2, challenge3)));

        authorization = new Authorization();
        authorization.setChallenges(Collections.unmodifiableList(challenges));
        authorization.setCombinations(Collections.unmodifiableList(combinations));
    }

    /**
     * Test that {@link Authorization#findChallenge(String)} does only find standalone
     * challenges, and nothing else.
     */
    @Test
    public void testFindChallenge() {
        // ProofOfPossesionChallenge is not available at all
        Challenge c1 = authorization.findChallenge(ProofOfPossessionChallenge.TYPE);
        assertThat(c1, is(nullValue()));

        // HttpChallenge is available as standalone challenge
        Challenge c2 = authorization.findChallenge(HttpChallenge.TYPE);
        assertThat(c2, is(notNullValue()));
        assertThat(c2, is(instanceOf(HttpChallenge.class)));

        // TlsSniChallenge is available, but not as standalone challenge
        Challenge c3 = authorization.findChallenge(TlsSniChallenge.TYPE);
        assertThat(c3, is(nullValue()));
    }

    /**
     * Test that {@link Authorization#findCombination(String...)} does only find proper
     * combinations.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testFindCombination() {
        // Standalone challenge
        Collection<Challenge> c1 = authorization.findCombination(HttpChallenge.TYPE);
        assertThat(c1, hasSize(1));
        assertThat(c1, contains(instanceOf(HttpChallenge.class)));

        // Available combined challenge
        Collection<Challenge> c2 = authorization.findCombination(DnsChallenge.TYPE, TlsSniChallenge.TYPE);
        assertThat(c2, hasSize(2));
        assertThat(c2, contains(instanceOf(DnsChallenge.class),
                        instanceOf(TlsSniChallenge.class)));

        // Order does not matter
        Collection<Challenge> c3 = authorization.findCombination(TlsSniChallenge.TYPE, DnsChallenge.TYPE);
        assertThat(c3, hasSize(2));
        assertThat(c3, contains(instanceOf(DnsChallenge.class),
                        instanceOf(TlsSniChallenge.class)));

        // Finds smaller combinations as well
        Collection<Challenge> c4 = authorization.findCombination(DnsChallenge.TYPE, TlsSniChallenge.TYPE, ProofOfPossessionChallenge.TYPE);
        assertThat(c4, hasSize(2));
        assertThat(c4, contains(instanceOf(DnsChallenge.class),
                        instanceOf(TlsSniChallenge.class)));

        // Finds the smallest possible combination
        Collection<Challenge> c5 = authorization.findCombination(DnsChallenge.TYPE, TlsSniChallenge.TYPE, HttpChallenge.TYPE);
        assertThat(c5, hasSize(1));
        assertThat(c5, contains(instanceOf(HttpChallenge.class)));

        // Finds only entire combinations
        Collection<Challenge> c6 = authorization.findCombination(DnsChallenge.TYPE);
        assertThat(c6, is(nullValue()));

        // Does not find challenges that have not been provided
        Collection<Challenge> c7 = authorization.findCombination(ProofOfPossessionChallenge.TYPE);
        assertThat(c7, is(nullValue()));
    }

    /**
     * Sets up a {@link Challenge}.
     *
     * @param typeName
     *            Type name to be set in the {@link Challenge}
     * @param instance
     *            Newly created {@link Challenge}
     * @return Initialized {@link Challenge}
     */
    private Challenge setupChallenge(String typeName, Challenge instance) {
        Map<String, Object> data = new HashMap<>();
        data.put("type", typeName);
        instance.unmarshall(data);
        return instance;
    }

}
