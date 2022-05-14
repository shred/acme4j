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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
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

    private final URL locationUrl = url("http://example.com/acme/account");

    /**
     * Test that {@link Authorization#findChallenge(String)} finds challenges.
     */
    @Test
    public void testFindChallenge() throws IOException {
        Authorization authorization = createChallengeAuthorization();

        // A snail mail challenge is not available at all
        Challenge c1 = authorization.findChallenge(SNAILMAIL_TYPE);
        assertThat(c1).isNull();

        // HttpChallenge is available
        Challenge c2 = authorization.findChallenge(Http01Challenge.TYPE);
        assertThat(c2).isNotNull();
        assertThat(c2).isInstanceOf(Http01Challenge.class);

        // Dns01Challenge is available
        Challenge c3 = authorization.findChallenge(Dns01Challenge.TYPE);
        assertThat(c3).isNotNull();
        assertThat(c3).isInstanceOf(Dns01Challenge.class);

        // TlsAlpn01Challenge is available
        Challenge c4 = authorization.findChallenge(TlsAlpn01Challenge.TYPE);
        assertThat(c4).isNotNull();
        assertThat(c4).isInstanceOf(TlsAlpn01Challenge.class);
    }

    /**
     * Test that {@link Authorization#findChallenge(Class)} finds challenges.
     */
    @Test
    public void testFindChallengeByType() throws IOException {
        Authorization authorization = createChallengeAuthorization();

        // A snail mail challenge is not available at all
        NonExistingChallenge c1 = authorization.findChallenge(NonExistingChallenge.class);
        assertThat(c1).isNull();

        // HttpChallenge is available
        Http01Challenge c2 = authorization.findChallenge(Http01Challenge.class);
        assertThat(c2).isNotNull();

        // Dns01Challenge is available
        Dns01Challenge c3 = authorization.findChallenge(Dns01Challenge.class);
        assertThat(c3).isNotNull();

        // TlsAlpn01Challenge is available
        TlsAlpn01Challenge c4 = authorization.findChallenge(TlsAlpn01Challenge.class);
        assertThat(c4).isNotNull();
    }

    /**
     * Test that {@link Authorization#findChallenge(String)} fails on duplicate
     * challenges.
     */
    @Test
    public void testFailDuplicateChallenges() throws IOException {
        assertThrows(AcmeProtocolException.class, () -> {
            Authorization authorization = createChallengeAuthorization();
            authorization.findChallenge(DUPLICATE_TYPE);
        });
    }

    /**
     * Test that authorization is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);
        provider.putTestChallenge("tls-alpn-01", TlsAlpn01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        auth.update();

        assertThat(auth.getIdentifier().getDomain()).isEqualTo("example.org");
        assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        assertThat(auth.isWildcard()).isFalse();
        assertThat(auth.getExpires()).isCloseTo("2016-01-02T17:12:40Z", within(1, ChronoUnit.SECONDS));
        assertThat(auth.getLocation()).isEqualTo(locationUrl);

        assertThat(auth.getChallenges()).containsExactlyInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE),
                        provider.getChallenge(TlsAlpn01Challenge.TYPE));

        provider.close();
    }

    /**
     * Test that wildcard authorization are correct.
     */
    @Test
    public void testWildcard() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationWildcardResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("dns-01", Dns01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        auth.update();

        assertThat(auth.getIdentifier().getDomain()).isEqualTo("example.org");
        assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        assertThat(auth.isWildcard()).isTrue();
        assertThat(auth.getExpires()).isCloseTo("2016-01-02T17:12:40Z", within(1, ChronoUnit.SECONDS));
        assertThat(auth.getLocation()).isEqualTo(locationUrl);

        assertThat(auth.getChallenges()).containsExactlyInAnyOrder(
                        provider.getChallenge(Dns01Challenge.TYPE));

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
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                requestWasSent.set(true);
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAuthorizationResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        provider.putTestChallenge("http-01", Http01Challenge::new);
        provider.putTestChallenge("dns-01", Dns01Challenge::new);
        provider.putTestChallenge("tls-alpn-01", TlsAlpn01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);

        // Lazy loading
        assertThat(requestWasSent).isFalse();
        assertThat(auth.getIdentifier().getDomain()).isEqualTo("example.org");
        assertThat(requestWasSent).isTrue();

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(auth.getIdentifier().getDomain()).isEqualTo("example.org");
        assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        assertThat(auth.isWildcard()).isFalse();
        assertThat(auth.getExpires()).isCloseTo("2016-01-02T17:12:40Z", within(1, ChronoUnit.SECONDS));
        assertThat(requestWasSent).isFalse();

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
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
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
        provider.putTestChallenge("tls-alpn-01", TlsAlpn01Challenge::new);

        Authorization auth = new Authorization(login, locationUrl);
        AcmeRetryAfterException ex = assertThrows(AcmeRetryAfterException.class, auth::update);
        assertThat(ex.getRetryAfter()).isEqualTo(retryAfter);

        assertThat(auth.getIdentifier().getDomain()).isEqualTo("example.org");
        assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        assertThat(auth.isWildcard()).isFalse();
        assertThat(auth.getExpires()).isCloseTo("2016-01-02T17:12:40Z", within(1, ChronoUnit.SECONDS));
        assertThat(auth.getLocation()).isEqualTo(locationUrl);

        assertThat(auth.getChallenges()).containsExactlyInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE),
                        provider.getChallenge(TlsAlpn01Challenge.TYPE));

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
                assertThat(json.get("status").asString()).isEqualTo("deactivated");
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
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
        provider.putTestChallenge("tls-alpn-01", TlsAlpn01Challenge::new);

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
            provider.putTestChallenge(TlsAlpn01Challenge.TYPE, TlsAlpn01Challenge::new);
            provider.putTestChallenge(DUPLICATE_TYPE, Challenge::new);

            Authorization authorization = new Authorization(login, locationUrl);
            authorization.setJSON(getJSON("authorizationChallenges"));
            return authorization;
        }
    }

    /**
     * Dummy challenge that is never going to be created.
     */
    private static class NonExistingChallenge extends Challenge {
        public NonExistingChallenge(Login login, JSON data) {
            super(login, data);
        }
    }

}
