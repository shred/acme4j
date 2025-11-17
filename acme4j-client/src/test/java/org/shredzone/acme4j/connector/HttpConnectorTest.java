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
package org.shredzone.acme4j.connector;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link HttpConnector}.
 */
public class HttpConnectorTest {

    /**
     * Test if a {@link java.net.http.HttpRequest.Builder} can be created and has proper
     * default values.
     */
    @Test
    public void testRequestBuilderDefaultValues() throws Exception {
        var url = URI.create("http://example.org:123/foo").toURL();
        var settings = new NetworkSettings();
        var httpClient = HttpClient.newBuilder().build();

        var connector = new HttpConnector(settings, httpClient);
        var request = connector.createRequestBuilder(url).build();

        assertThat(request.uri().toString()).isEqualTo(url.toExternalForm());
        assertThat(request.timeout().orElseThrow()).isEqualTo(settings.getTimeout());
        assertThat(request.headers().firstValue("User-Agent").orElseThrow())
                .isEqualTo(HttpConnector.defaultUserAgent());
    }

    /**
     * Tests that the user agent is correct.
     */
    @Test
    public void testUserAgent() {
        var userAgent = HttpConnector.defaultUserAgent();
        assertThat(userAgent).contains("acme4j/");
        assertThat(userAgent).contains("Java/");
    }

    /**
     * Test that getHttpClient returns the HttpClient passed to the constructor.
     */
    @Test
    public void testGetHttpClient() {
        var settings = new NetworkSettings();
        var httpClient = HttpClient.newBuilder().build();

        var connector = new HttpConnector(settings, httpClient);

        // Should return the same client instance that was passed in
        assertThat(connector.getHttpClient()).isSameAs(httpClient);
    }

}
