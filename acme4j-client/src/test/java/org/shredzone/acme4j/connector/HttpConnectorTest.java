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
import static org.mockito.Mockito.mock;

import java.net.Authenticator;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link HttpConnector}.
 */
public class HttpConnectorTest {

    /**
     * Test if a {@link java.net.http.HttpClient.Builder} can be created and has proper
     * default values.
     */
    @Test
    public void testClientBuilderDefaultValues() {
        var settings = new NetworkSettings();

        var connector = new HttpConnector(settings);
        var client = connector.createClientBuilder().build();

        assertThat(client.connectTimeout().orElseThrow()).isEqualTo(settings.getTimeout());
        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
        assertThat(client.authenticator()).isEmpty();
    }

    /**
     * Test if a {@link java.net.http.HttpClient.Builder} can be created and if it is
     * preconfigured properly.
     */
    @Test
    public void testClientBuilder() {
        var timeout = Duration.ofSeconds(50);
        var authenticator = mock(Authenticator.class);

        var settings = new NetworkSettings();
        settings.setTimeout(timeout);
        settings.setAuthenticator(authenticator);

        var connector = new HttpConnector(settings);
        var client = connector.createClientBuilder().build();

        assertThat(client.connectTimeout().orElseThrow()).isEqualTo(timeout);
        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
        assertThat(client.authenticator().orElseThrow()).isSameAs(authenticator);
    }

    /**
     * Test if a {@link java.net.http.HttpRequest.Builder} can be created and has proper
     * default values.
     */
    @Test
    public void testRequestBuilderDefaultValues() throws Exception {
        var url = URI.create("http://example.org:123/foo").toURL();
        var settings = new NetworkSettings();

        var connector = new HttpConnector(settings);
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
     * Test that getHttpClient returns a new client when reuse is disabled.
     */
    @Test
    public void testGetHttpClientWithoutReuse() {
        var settings = new NetworkSettings();
        settings.setClientReuseEnabled(false);

        var connector = new HttpConnector(settings);

        var client1 = connector.getHttpClient();
        var client2 = connector.getHttpClient();

        // Each call should return a new client instance
        assertThat(client1).isNotSameAs(client2);
    }

    /**
     * Test that getHttpClient returns the same client when reuse is enabled.
     */
    @Test
    public void testGetHttpClientWithReuse() {
        var settings = new NetworkSettings();
        settings.setClientReuseEnabled(true);

        var connector = new HttpConnector(settings);

        var client1 = connector.getHttpClient();
        var client2 = connector.getHttpClient();

        // Both calls should return the same client instance
        assertThat(client1).isSameAs(client2);
    }

    /**
     * Test that getHttpClient with reuse enabled is thread-safe.
     */
    @Test
    public void testGetHttpClientThreadSafety() throws Exception {
        var settings = new NetworkSettings();
        settings.setClientReuseEnabled(true);

        var connector = new HttpConnector(settings);

        var threads = new Thread[10];
        var clients = new java.net.http.HttpClient[threads.length];

        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                clients[index] = connector.getHttpClient();
            });
        }

        for (var thread : threads) {
            thread.start();
        }

        for (var thread : threads) {
            thread.join();
        }

        // All threads should get the same client instance
        var firstClient = clients[0];
        for (var client : clients) {
            assertThat(client).isSameAs(firstClient);
        }
    }

}
