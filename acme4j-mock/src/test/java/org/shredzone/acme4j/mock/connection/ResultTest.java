/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static java.util.Collections.singletonList;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.mock.model.MockResource;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Unit tests for {@link Result}.
 */
public class ResultTest {

    /**
     * Test JSON type results.
     */
    @Test
    public void testJSONResult() throws MalformedURLException {
        String jsonRaw = "{\"test\": 123}";
        JSON json = JSON.parse(jsonRaw);
        URL location = new URL("https://acme.test/foo");
        Instant retryAfter = Instant.now().plus(12, ChronoUnit.HOURS);

        Result simpleResult = new Result(json);
        assertThat(simpleResult.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(simpleResult.getLocation(), is(nullValue()));
        assertThat(simpleResult.getRetryAfter(), is(nullValue()));
        assertThat(simpleResult.getCertificate(), is(nullValue()));

        Result locationResult = new Result(json, location);
        assertThat(locationResult.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(locationResult.getLocation(), is(location));
        assertThat(locationResult.getRetryAfter(), is(nullValue()));
        assertThat(locationResult.getCertificate(), is(nullValue()));

        Result retryResult1 = new Result(json, location, retryAfter);
        assertThat(retryResult1.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(retryResult1.getLocation(), is(location));
        assertThat(retryResult1.getRetryAfter(), is(retryAfter));
        assertThat(retryResult1.getCertificate(), is(nullValue()));

        Result retryResult2 = locationResult.withRetryAfter(retryAfter);
        assertThat(retryResult2.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(retryResult2.getLocation(), is(location));
        assertThat(retryResult2.getRetryAfter(), is(retryAfter));
        assertThat(retryResult2.getCertificate(), is(nullValue()));
    }

    /**
     * Test JSON type results based on a {@link MockResource}.
     */
    @Test
    public void testMockResourceResult() throws MalformedURLException {
        String jsonRaw = "{\"test\": 123}";
        JSON json = JSON.parse(jsonRaw);
        URL location = new URL("https://acme.test/foo");
        Instant retryAfter = Instant.now().plus(12, ChronoUnit.HOURS);

        MockResource resource = new MockResource() {
            @Override
            public URL getLocation() {
                return location;
            }

            @Override
            public JSON toJSON() {
                return json;
            }
        };

        Result result = new Result(resource);
        assertThat(result.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(result.getLocation(), is(location));
        assertThat(result.getRetryAfter(), is(nullValue()));
        assertThat(result.getCertificate(), is(nullValue()));

        Result retryResult = result.withRetryAfter(retryAfter);
        assertThat(retryResult.getJSON().toString(), sameJSONAs(jsonRaw));
        assertThat(retryResult.getLocation(), is(location));
        assertThat(retryResult.getRetryAfter(), is(retryAfter));
        assertThat(retryResult.getCertificate(), is(nullValue()));
    }

    /**
     * Test certificate type results.
     */
    @Test
    public void testCertificateResult() {
        List<X509Certificate> certs = singletonList(mock(X509Certificate.class));

        Result result = new Result(certs);
        assertThat(result.getCertificate(), is(certs));
        assertThat(result.getJSON(), is(nullValue()));
        assertThat(result.getLocation(), is(nullValue()));
        assertThat(result.getRetryAfter(), is(nullValue()));

        try {
            result.withRetryAfter(Instant.now());
            fail("RetryAfter accepted by certificate type result");
        } catch (IllegalStateException ex) {
            // expected
        }
    }

    /**
     * Test the empty result.
     */
    @Test
    public void testEmptyResult() {
        Result result = Result.empty();

        assertThat(result.getCertificate(), is(nullValue()));
        assertThat(result.getJSON(), is(nullValue()));
        assertThat(result.getLocation(), is(nullValue()));
        assertThat(result.getRetryAfter(), is(nullValue()));

        try {
            result.withRetryAfter(Instant.now());
            fail("RetryAfter accepted by empty result");
        } catch (IllegalStateException ex) {
            // expected
        }
    }

}
