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
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.util.TestUtils.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.JSONBuilder;

/**
 * Unit tests for {@link Authorization}.
 */
public class AuthorizationTest {

    private static final String SNAILMAIL_TYPE = "snail-01"; // a non-existent challenge

    private URI locationUri = URI.create("http://example.com/acme/registration");;

    /**
     * Test that {@link Authorization#findChallenge(String)} does only find standalone
     * challenges, and nothing else.
     */
    @Test
    public void testFindChallenge() throws IOException {
        Authorization authorization = createChallengeAuthorization();

        // A snail mail challenge is not available at all
        Challenge c1 = authorization.findChallenge(SNAILMAIL_TYPE);
        assertThat(c1, is(nullValue()));

        // HttpChallenge is available as standalone challenge
        Challenge c2 = authorization.findChallenge(Http01Challenge.TYPE);
        assertThat(c2, is(notNullValue()));
        assertThat(c2, is(instanceOf(Http01Challenge.class)));

        // TlsSniChallenge is available, but not as standalone challenge
        Challenge c3 = authorization.findChallenge(TlsSni02Challenge.TYPE);
        assertThat(c3, is(nullValue()));
    }

    /**
     * Test that {@link Authorization#findCombination(String...)} does only find proper
     * combinations.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testFindCombination() throws IOException {
        Authorization authorization = createChallengeAuthorization();

        // Standalone challenge
        Collection<Challenge> c1 = authorization.findCombination(Http01Challenge.TYPE);
        assertThat(c1, hasSize(1));
        assertThat(c1, contains(instanceOf(Http01Challenge.class)));

        // Available combined challenge
        Collection<Challenge> c2 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni02Challenge.TYPE);
        assertThat(c2, hasSize(2));
        assertThat(c2, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni02Challenge.class)));

        // Order does not matter
        Collection<Challenge> c3 = authorization.findCombination(TlsSni02Challenge.TYPE, Dns01Challenge.TYPE);
        assertThat(c3, hasSize(2));
        assertThat(c3, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni02Challenge.class)));

        // Finds smaller combinations as well
        Collection<Challenge> c4 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni02Challenge.TYPE, SNAILMAIL_TYPE);
        assertThat(c4, hasSize(2));
        assertThat(c4, contains(instanceOf(Dns01Challenge.class),
                        instanceOf(TlsSni02Challenge.class)));

        // Finds the smallest possible combination
        Collection<Challenge> c5 = authorization.findCombination(Dns01Challenge.TYPE, TlsSni02Challenge.TYPE, Http01Challenge.TYPE);
        assertThat(c5, hasSize(1));
        assertThat(c5, contains(instanceOf(Http01Challenge.class)));

        // Finds only entire combinations
        Collection<Challenge> c6 = authorization.findCombination(Dns01Challenge.TYPE);
        assertThat(c6, is(nullValue()));

        // Does not find challenges that have not been provided
        Collection<Challenge> c7 = authorization.findCombination(SNAILMAIL_TYPE);
        assertThat(c7, is(nullValue()));
    }

    /**
     * Test that authorization is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URI uri, Session session) {
                assertThat(uri, is(locationUri));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("updateAuthorizationResponse");
            }
        };

        Session session = provider.createSession();

        Http01Challenge httpChallenge = new Http01Challenge(session);
        Dns01Challenge dnsChallenge = new Dns01Challenge(session);
        provider.putTestChallenge("http-01", httpChallenge);
        provider.putTestChallenge("dns-01", dnsChallenge);

        Authorization auth = new Authorization(session, locationUri);
        auth.update();

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUri));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        assertThat(auth.getCombinations(), hasSize(2));
        assertThat(auth.getCombinations().get(0), containsInAnyOrder(
                        (Challenge) httpChallenge));
        assertThat(auth.getCombinations().get(1), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        provider.close();
    }

    /**
     * Test lazy loading.
     */
    @Test
    public void testLazyLoading() throws Exception {
        final AtomicBoolean requestWasSent = new AtomicBoolean(false);

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URI uri, Session session) {
                requestWasSent.set(true);
                assertThat(uri, is(locationUri));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("updateAuthorizationResponse");
            }
        };

        Session session = provider.createSession();

        provider.putTestChallenge("http-01", new Http01Challenge(session));
        provider.putTestChallenge("dns-01", new Dns01Challenge(session));

        Authorization auth = new Authorization(session, locationUri);

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(auth.getDomain(), is("example.org"));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that authorization is properly updated, with retry-after header set.
     */
    @Test
    public void testUpdateRetryAfter() throws Exception {
        final long retryAfter = System.currentTimeMillis() + 30 * 1000L;

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URI uri, Session session) {
                assertThat(uri, is(locationUri));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("updateAuthorizationResponse");
            }

            @Override
            public Date getRetryAfterHeader() {
                return new Date(retryAfter);
            }
        };

        Session session = provider.createSession();

        Http01Challenge httpChallenge = new Http01Challenge(session);
        Dns01Challenge dnsChallenge = new Dns01Challenge(session);
        provider.putTestChallenge("http-01", httpChallenge);
        provider.putTestChallenge("dns-01", dnsChallenge);

        Authorization auth = new Authorization(session, locationUri);

        try {
            auth.update();
            fail("Expected AcmeRetryAfterException");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(new Date(retryAfter)));
        }

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUri));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        assertThat(auth.getCombinations(), hasSize(2));
        assertThat(auth.getCombinations().get(0), containsInAnyOrder(
                        (Challenge) httpChallenge));
        assertThat(auth.getCombinations().get(1), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        provider.close();
    }

    /**
     * Test that an authorization can be deactivated.
     */
    @Test
    public void testDeactivate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                Map<String, Object> claimMap = claims.toMap();
                assertThat(claimMap.get("resource"), is((Object) "authz"));
                assertThat(claimMap.get("status"), is((Object) "deactivated"));
                assertThat(uri, is(locationUri));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }
        };

        Authorization auth = new Authorization(provider.createSession(), locationUri);
        auth.deactivate();

        provider.close();
    }

    /**
     * Creates an {@link Authorization} instance with a set of challenges.
     */
    private Authorization createChallengeAuthorization() throws IOException {
        try (TestableConnectionProvider provider = new TestableConnectionProvider()) {
            Session session = provider.createSession();

            provider.putTestChallenge(Http01Challenge.TYPE, new Http01Challenge(session));
            provider.putTestChallenge(Dns01Challenge.TYPE, new Dns01Challenge(session));
            provider.putTestChallenge(TlsSni02Challenge.TYPE, new TlsSni02Challenge(session));

            Authorization authorization = new Authorization(session, locationUri);
            authorization.unmarshalAuthorization(getJsonAsMap("authorizationChallenges"));
            return authorization;
        }
    }

}
