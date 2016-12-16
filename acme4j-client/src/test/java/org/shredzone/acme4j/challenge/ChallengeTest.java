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
import static org.shredzone.acme4j.util.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Date;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;
import org.shredzone.acme4j.util.TimestampParser;

/**
 * Unit tests for {@link Challenge}.
 */
public class ChallengeTest {
    private Session session;
    private URI resourceUri = URI.create("https://example.com/acme/some-resource");
    private URI locationUri = URI.create("https://example.com/acme/some-location");

    @Before
    public void setup() throws IOException {
        session = TestUtils.session();
    }

    /**
     * Test that a challenge is properly restored.
     */
    @Test
    public void testChallenge() throws Exception {
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
                return getJsonAsMap("updateHttpChallengeResponse");
            }
        };

        Session session = provider.createSession();

        provider.putTestChallenge(Http01Challenge.TYPE, new Http01Challenge(session));

        Http01Challenge challenge = Challenge.bind(session, locationUri);

        assertThat(challenge.getType(), is(Http01Challenge.TYPE));
        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUri));
        assertThat(challenge.getToken(), is("IlirfxKKXAsHtmzK29Pj8A"));

        provider.close();
    }

    /**
     * Test that after unmarshalling, the challenge properties are set correctly.
     */
    @Test
    public void testUnmarshall() throws URISyntaxException, MalformedURLException {
        Challenge challenge = new Challenge(session);

        // Test default values
        assertThat(challenge.getType(), is(nullValue()));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getLocation(), is(nullValue()));
        assertThat(challenge.getValidated(), is(nullValue()));

        // Unmarshall a challenge JSON
        challenge.unmarshall(TestUtils.getJsonAsMap("genericChallenge"));

        // Test unmarshalled values
        assertThat(challenge.getType(), is("generic-01"));
        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(new URI("http://example.com/challenge/123")));
        assertThat(challenge.getValidated(), is(TimestampParser.parse("2015-12-12T17:19:36.336785823Z")));
        assertThat((String) challenge.get("type"), is("generic-01"));
        assertThat(challenge.getUrl("uri"), is(new URL("http://example.com/challenge/123")));
        assertThat(challenge.get("not-present"), is(nullValue()));
        assertThat(challenge.getUrl("not-present-url"), is(nullValue()));

        try {
            challenge.getUrl("type");
            fail("bad URL is not detected");
        } catch (AcmeProtocolException ex) {
            // expected
        }
    }

    /**
     * Test that {@link Challenge#respond(ClaimBuilder)} contains the type.
     */
    @Test
    public void testRespond() throws JoseException {
        String json = TestUtils.getJson("genericChallenge");

        Challenge challenge = new Challenge(session);
        challenge.unmarshall(JsonUtil.parseJson(json));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"type\"=\"generic-01\"}"));
    }

    /**
     * Test that an exception is thrown on challenge type mismatch.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testNotAcceptable() throws URISyntaxException {
        Http01Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("dnsChallenge"));
    }

    /**
     * Test that a challenge can be triggered.
     */
    @Test
    public void testTrigger() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("triggerHttpChallengeRequest")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("triggerHttpChallengeResponse");
            }
        };

        Session session = provider.createSession();

        Http01Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(getJsonAsMap("triggerHttpChallenge"));

        challenge.trigger();

        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getLocation(), is(locationUri));

        provider.close();
    }

    /**
     * Test that a challenge is properly updated.
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
                return getJsonAsMap("updateHttpChallengeResponse");
            }
        };

        Session session = provider.createSession();

        Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(getJsonAsMap("triggerHttpChallengeResponse"));

        challenge.update();

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUri));

        provider.close();
    }

    /**
     * Test that a challenge is properly updated, with Retry-After header.
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
                return getJsonAsMap("updateHttpChallengeResponse");
            }

            @Override
            public Date getRetryAfterHeader() {
                return new Date(retryAfter);
            }
        };

        Session session = provider.createSession();

        Challenge challenge = new Http01Challenge(session);
        challenge.unmarshall(getJsonAsMap("triggerHttpChallengeResponse"));

        try {
            challenge.update();
            fail("Expected AcmeRetryAfterException");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(new Date(retryAfter)));
        }

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUri));

        provider.close();
    }

    /**
     * Test that null is handled properly.
     */
    @Test
    public void testNullChallenge() throws Exception {
        try {
            Challenge.bind(session, null);
            fail("locationUri accepts null");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            Challenge.bind(null, locationUri);
            fail("session accepts null");
        } catch (NullPointerException ex) {
            // expected
        }
    }

    /**
     * Test that an exception is thrown on a bad location URI.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testBadBind() throws Exception {
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
                return getJsonAsMap("updateRegistrationResponse");
            }
        };

        Session session = provider.createSession();
        Challenge.bind(session, locationUri);

        provider.close();
    }

    /**
     * Test that unmarshalling something different like a challenge fails.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testBadUnmarshall() {
        Challenge challenge = new Challenge(session);
        challenge.unmarshall(TestUtils.getJsonAsMap("updateRegistrationResponse"));
    }

    /**
     * Test that challenge serialization works correctly.
     */
    @Test
    public void testSerialization() throws IOException, ClassNotFoundException {
        Http01Challenge originalChallenge = new Http01Challenge(session);
        originalChallenge.unmarshall(TestUtils.getJsonAsMap("httpChallenge"));

        // Serialize
        byte[] data;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
                oos.writeObject(originalChallenge);
            }
            data = out.toByteArray();
        }

        // Deserialize
        Challenge testChallenge;
        try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {
            try (ObjectInputStream ois = new ObjectInputStream(in)) {
                testChallenge = (Challenge) ois.readObject();
            }
        }

        assertThat(testChallenge, not(sameInstance((Challenge) originalChallenge)));
        assertThat(testChallenge, is(instanceOf(Http01Challenge.class)));
        assertThat(testChallenge.getType(), is(Http01Challenge.TYPE));
        assertThat(testChallenge.getStatus(), is(Status.PENDING));
        assertThat(((Http01Challenge )testChallenge).getToken(), is("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ"));
    }

}
