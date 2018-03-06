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
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.toolbox.TestUtils.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link Authorization}.
 */
public class AuthorizationTest {

    private static final String SNAILMAIL_TYPE = "snail-01"; // a non-existent challenge
    private static final String DUPLICATE_TYPE = "duplicate-01"; // a duplicate challenge

    private URL locationUrl = url("http://example.com/acme/account");

    /**
     * Test that {@link Authorization#findChallenge(String)} finds challenges.
     */
    @Test
    public void testFindChallenge() throws IOException {
        Authorization authorization = createChallengeAuthorization();

        // A snail mail challenge is not available at all
        Challenge c1 = authorization.findChallenge(SNAILMAIL_TYPE);
        assertThat(c1, is(nullValue()));

        // HttpChallenge is available
        Challenge c2 = authorization.findChallenge(Http01Challenge.TYPE);
        assertThat(c2, is(notNullValue()));
        assertThat(c2, is(instanceOf(Http01Challenge.class)));

        // Dns01Challenge is available
        Challenge c3 = authorization.findChallenge(Dns01Challenge.TYPE);
        assertThat(c3, is(notNullValue()));
        assertThat(c3, is(instanceOf(Dns01Challenge.class)));
    }

    /**
     * Test that {@link Authorization#findChallenge(String)} fails on duplicate
     * challenges.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testFailDuplicateChallenges() throws IOException {
        Authorization authorization = createChallengeAuthorization();
        authorization.findChallenge(DUPLICATE_TYPE);
    }

    /**
     * Test that authorization is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        auth.update();

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.isWildcard(), is(false));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUrl));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE)));

        provider.close();
    }

    /**
     * Test that wildcard authorization are correct.
     */
    @Test
    public void testWildcard() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationWildcardResponse");
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        auth.update();

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.isWildcard(), is(true));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUrl));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        provider.getChallenge(Dns01Challenge.TYPE)));

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
            public void sendRequest(URL url, Session session) {
                requestWasSent.set(true);
                assertThat(url, is(locationUrl));
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(auth.getDomain(), is("example.org"));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.isWildcard(), is(false));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that authorization is properly updated, with retry-after header set.
     */
    @Test
    public void testUpdateRetryAfter() throws Exception {
        final Instant retryAfter = Instant.now().plus(Duration.ofSeconds(30));

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                throw new AcmeRetryAfterException(message, retryAfter);
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);

        try {
            auth.update();
            fail("Expected AcmeRetryAfterException");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(retryAfter));
        }

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.isWildcard(), is(false));
        assertThat(auth.getExpires(), is(parseTimestamp("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUrl));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE)));

        provider.close();
    }

    /**
     * Test that an authorization can be deactivated.
     */
    @Test
    public void testDeactivate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                JSON json = claims.toJSON();
                assertThat(json.get("status").asString(), is("deactivated"));
                assertThat(url, is(locationUrl));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        auth.deactivate();

        provider.close();
    }

    /**
     * Creates an {@link Authorization} instance with a set of challenges.
     */
    private Authorization createChallengeAuthorization() throws IOException {
        try (TestableConnectionProvider provider = new TestableConnectionProvider()) {
            Login login = provider.createLogin();

            provider.putTestChallenge(Http01Challenge.TYPE, Http01Challenge::new);
            provider.putTestChallenge(Dns01Challenge.TYPE, Dns01Challenge::new);
            provider.putTestChallenge(DUPLICATE_TYPE, Challenge::new);

            Authorization authorization = new Authorization(login, locationUrl);
            authorization.setJSON(getJSON("authorizationChallenges"));
            return authorization;
        }
    }

}
