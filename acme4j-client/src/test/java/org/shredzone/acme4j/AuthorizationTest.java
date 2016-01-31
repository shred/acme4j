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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.ProofOfPossession01Challenge;
import org.shredzone.acme4j.challenge.TlsSni01Challenge;

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
        Challenge challenge1 = setupChallenge(Http01Challenge.TYPE, new Http01Challenge());
        Challenge challenge2 = setupChallenge(Dns01Challenge.TYPE, new Dns01Challenge());
        Challenge challenge3 = setupChallenge(TlsSni01Challenge.TYPE, new TlsSni01Challenge());

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
     * Test getters and setters.
     */
    @Test
    public void testGetterAndSetter() {
        Date expiry = new Date();

        Authorization auth = new Authorization();

        assertThat(auth.getDomain(), is(nullValue()));
        assertThat(auth.getStatus(), is(nullValue()));
        assertThat(auth.getExpires(), is(nullValue()));
        assertThat(auth.getChallenges(), is(nullValue()));
        assertThat(auth.getCombinations(), is(nullValue()));

        auth.setDomain("example.com");
        auth.setStatus(Status.INVALID);
        auth.setExpires(expiry);
        auth.setChallenges(authorization.getChallenges());
        auth.setCombinations(authorization.getCombinations());

        assertThat(auth.getDomain(), is("example.com"));
        assertThat(auth.getStatus(), is(Status.INVALID));
        assertThat(auth.getExpires(), is(expiry));
        assertThat(auth.getChallenges(), is(sameInstance(authorization.getChallenges())));
        assertThat(auth.getCombinations(), is(sameInstance(authorization.getCombinations())));
    }

    /**
     * Test that {@link Authorization#findChallenge(String)} does only find standalone
     * challenges, and nothing else.
     */
    @Test
    public void testFindChallenge() {
        // ProofOfPossesionChallenge is not available at all
        Challenge c1 = authorization.findChallenge(ProofOfPossession01Challenge.TYPE);
        assertThat(c1, is(nullValue()));

        // HttpChallenge is available as standalone challenge
        Challenge c2 = authorization.findChallenge(Http01Challenge.TYPE);
        assertThat(c2, is(notNullValue()));
        assertThat(c2, is(instanceOf(Http01Challenge.class)));

        // TlsSniChallenge is available, but not as standalone challenge
        Challenge c3 = authorization.findChallenge(TlsSni01Challenge.TYPE);
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
        Collection<Challenge> c1 = authorization.findCombination(Http01Challenge.TYPE);
        assertThat(c1, hasSize(1));
        assertThat(c1, contains(instanceOf(Http01Challenge.class)));

        // Available combined challenge
        Collection<Challenge> c2 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni01Challenge.TYPE);
        assertThat(c2, hasSize(2));
        assertThat(c2, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni01Challenge.class)));

        // Order does not matter
        Collection<Challenge> c3 = authorization.findCombination(TlsSni01Challenge.TYPE, Dns01Challenge.TYPE);
        assertThat(c3, hasSize(2));
        assertThat(c3, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni01Challenge.class)));

        // Finds smaller combinations as well
        Collection<Challenge> c4 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni01Challenge.TYPE, ProofOfPossession01Challenge.TYPE);
        assertThat(c4, hasSize(2));
        assertThat(c4, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni01Challenge.class)));

        // Finds the smallest possible combination
        Collection<Challenge> c5 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni01Challenge.TYPE, Http01Challenge.TYPE);
        assertThat(c5, hasSize(1));
        assertThat(c5, contains(instanceOf(Http01Challenge.class)));

        // Finds only entire combinations
        Collection<Challenge> c6 = authorization.findCombination(Dns01Challenge.TYPE);
        assertThat(c6, is(nullValue()));

        // Does not find challenges that have not been provided
        Collection<Challenge> c7 = authorization.findCombination(ProofOfPossession01Challenge.TYPE);
        assertThat(c7, is(nullValue()));
    }

    /**
     * Test constructors.
     */
    @Test
    public void testConstructor() throws URISyntaxException {
        Authorization auth1 = new Authorization();
        assertThat(auth1.getLocation(), is(nullValue()));

        Authorization auth2 = new Authorization(new URI("http://example.com/acme/12345"));
        assertThat(auth2.getLocation(), is(new URI("http://example.com/acme/12345")));
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
