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
package org.shredzone.acme4j.connector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link NetworkSettings}.
 */
public class NetworkSettingsTest {

    /**
     * Test getters and setters.
     */
    @Test
    public void testGettersAndSetters() {
        var settings = new NetworkSettings();

        var proxyAddress = new InetSocketAddress("10.0.0.1", 8080);
        var proxySelector = ProxySelector.of(proxyAddress);

        assertThat(settings.getProxySelector()).isSameAs(HttpClient.Builder.NO_PROXY);
        settings.setProxySelector(proxySelector);
        assertThat(settings.getProxySelector()).isSameAs(proxySelector);
        settings.setProxySelector(null);
        assertThat(settings.getProxySelector()).isEqualTo(HttpClient.Builder.NO_PROXY);

        assertThat(settings.getTimeout()).isEqualTo(Duration.ofSeconds(10));
        settings.setTimeout(Duration.ofMillis(5120));
        assertThat(settings.getTimeout()).isEqualTo(Duration.ofMillis(5120));

        var defaultAuthenticator = Authenticator.getDefault();
        assertThat(settings.getAuthenticator()).isNull();
        settings.setAuthenticator(defaultAuthenticator);
        assertThat(settings.getAuthenticator()).isSameAs(defaultAuthenticator);

        assertThat(settings.isCompressionEnabled()).isTrue();
        settings.setCompressionEnabled(false);
        assertThat(settings.isCompressionEnabled()).isFalse();
    }

    @Test
    public void testInvalidTimeouts() {
        var settings = new NetworkSettings();

        assertThrows(IllegalArgumentException.class,
                () -> settings.setTimeout(null),
                "timeout accepted null");
        assertThrows(IllegalArgumentException.class,
                () -> settings.setTimeout(Duration.ZERO),
                "timeout accepted zero duration");
        assertThrows(IllegalArgumentException.class,
                () -> settings.setTimeout(Duration.ofSeconds(20).negated()),
                "timeout accepted negative duration");
    }

}
