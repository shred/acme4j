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

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Challenge}.
 */
public class ChallengeTest {
    private final URL locationUrl = url("https://example.com/acme/some-location");

    /**
     * Test that after unmarshaling, the challenge properties are set correctly.
     */
    @Test
    public void testUnmarshal() {
        var challenge = new Challenge(TestUtils.login(), getJSON("genericChallenge"));

        // Test unmarshalled values
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(challenge.getType()).isEqualTo("generic-01");
            softly.assertThat(challenge.getStatus()).isEqualTo(Status.INVALID);
            softly.assertThat(challenge.getLocation()).isEqualTo(url("http://example.com/challenge/123"));
            softly.assertThat(challenge.getValidated().orElseThrow())
                    .isCloseTo("2015-12-12T17:19:36.336Z", within(1, ChronoUnit.MILLIS));
            softly.assertThat(challenge.getJSON().get("type").asString()).isEqualTo("generic-01");
            softly.assertThat(challenge.getJSON().get("url").asURL()).isEqualTo(url("http://example.com/challenge/123"));

            var error = challenge.getError().orElseThrow();
            softly.assertThat(error.getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:incorrectResponse"));
            softly.assertThat(error.getDetail().orElseThrow()).isEqualTo("bad token");
            softly.assertThat(error.getInstance().orElseThrow())
                    .isEqualTo(URI.create("http://example.com/documents/faq.html"));
        }
    }

    /**
     * Test that {@link Challenge#prepareResponse(JSONBuilder)} contains the type.
     */
    @Test
    public void testRespond() {
        var challenge = new Challenge(TestUtils.login(), getJSON("genericChallenge"));

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

    /**
     * Test that an exception is thrown on challenge type mismatch.
     */
    @Test
    public void testNotAcceptable() {
        assertThrows(AcmeProtocolException.class, () ->
            new Http01Challenge(TestUtils.login(), getJSON("dnsChallenge"))
        );
    }

    /**
     * Test that a challenge can be triggered.
     */
    @Test
    public void testTrigger() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("triggerHttpChallengeRequest").toString());
                assertThat(login).isNotNull();
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("triggerHttpChallengeResponse");
            }
        };

        var login = provider.createLogin();

        var challenge = new Http01Challenge(login, getJSON("triggerHttpChallenge"));

        challenge.trigger();

        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getLocation()).isEqualTo(locationUrl);

        provider.close();
    }

    /**
     * Test that a challenge is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateHttpChallengeResponse");
            }
        };

        var login = provider.createLogin();

        var challenge = new Http01Challenge(login, getJSON("triggerHttpChallengeResponse"));

        challenge.update();

        assertThat(challenge.getStatus()).isEqualTo(Status.VALID);
        assertThat(challenge.getLocation()).isEqualTo(locationUrl);

        provider.close();
    }

    /**
     * Test that a challenge is properly updated, with Retry-After header.
     */
    @Test
    public void testUpdateRetryAfter() throws Exception {
        var retryAfter = Instant.now().plus(Duration.ofSeconds(30));

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateHttpChallengeResponse");
            }

            @Override
            public Optional<Instant> getRetryAfter() {
                return Optional.of(retryAfter);
            }
        };

        var login = provider.createLogin();

        var challenge = new Http01Challenge(login, getJSON("triggerHttpChallengeResponse"));
        var returnedRetryAfter = challenge.fetch();
        assertThat(returnedRetryAfter).hasValue(retryAfter);

        assertThat(challenge.getStatus()).isEqualTo(Status.VALID);
        assertThat(challenge.getLocation()).isEqualTo(locationUrl);

        provider.close();
    }

    /**
     * Test that unmarshalling something different like a challenge fails.
     */
    @Test
    public void testBadUnmarshall() {
        assertThrows(AcmeProtocolException.class, () ->
            new Challenge(TestUtils.login(), getJSON("updateAccountResponse"))
        );
    }

}
