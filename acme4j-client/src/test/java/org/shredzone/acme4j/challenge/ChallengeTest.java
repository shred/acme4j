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
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;

import org.junit.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Challenge}.
 */
public class ChallengeTest {
    private URL locationUrl = url("https://example.com/acme/some-location");

    /**
     * Test that after unmarshaling, the challenge properties are set correctly.
     */
    @Test
    public void testUnmarshal() {
        Challenge challenge = new Challenge(TestUtils.login(), getJSON("genericChallenge"));

        // Test unmarshalled values
        assertThat(challenge.getType(), is("generic-01"));
        assertThat(challenge.getStatus(), is(Status.INVALID));
        assertThat(challenge.getLocation(), is(url("http://example.com/challenge/123")));
        assertThat(challenge.getValidated(), is(parseTimestamp("2015-12-12T17:19:36.336785823Z")));
        assertThat(challenge.getJSON().get("type").asString(), is("generic-01"));
        assertThat(challenge.getJSON().get("url").asURL(), is(url("http://example.com/challenge/123")));

        Problem error = challenge.getError();
        assertThat(error, is(notNullValue()));
        assertThat(error.getType(), is(URI.create("urn:ietf:params:acme:error:incorrectResponse")));
        assertThat(error.getDetail(), is("bad token"));
        assertThat(error.getInstance(), is(URI.create("http://example.com/documents/faq.html")));
    }

    /**
     * Test that {@link Challenge#prepareResponse(JSONBuilder)} contains the type.
     */
    @Test
    public void testRespond() {
        Challenge challenge = new Challenge(TestUtils.login(), getJSON("genericChallenge"));

        JSONBuilder response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThat(response.toString(), sameJSONAs("{}"));
    }

    /**
     * Test that an exception is thrown on challenge type mismatch.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testNotAcceptable() {
        new Http01Challenge(TestUtils.login(), getJSON("dnsChallenge"));
    }

    /**
     * Test that a challenge can be triggered.
     */
    @Test
    public void testTrigger() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(locationUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("triggerHttpChallengeRequest").toString()));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("triggerHttpChallengeResponse");
            }
        };

        Login login = provider.createLogin();

        Http01Challenge challenge = new Http01Challenge(login, getJSON("triggerHttpChallenge"));

        challenge.trigger();

        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test that a challenge is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateHttpChallengeResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                // Just do nothing
            }
        };

        Login login = provider.createLogin();

        Challenge challenge = new Http01Challenge(login, getJSON("triggerHttpChallengeResponse"));

        challenge.update();

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test that a challenge is properly updated, with Retry-After header.
     */
    @Test
    public void testUpdateRetryAfter() throws Exception {
        final Instant retryAfter = Instant.now().plus(Duration.ofSeconds(30));

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateHttpChallengeResponse");
            }


            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                throw new AcmeRetryAfterException(message, retryAfter);
            }
        };

        Login login = provider.createLogin();

        Challenge challenge = new Http01Challenge(login, getJSON("triggerHttpChallengeResponse"));

        try {
            challenge.update();
            fail("Expected AcmeRetryAfterException");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(retryAfter));
        }

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test that unmarshalling something different like a challenge fails.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testBadUnmarshall() {
        new Challenge(TestUtils.login(), getJSON("updateAccountResponse"));
    }

}
