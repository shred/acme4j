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
import java.net.ProxySelector;
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

        var proxyAddress = new InetSocketAddress("198.51.100.1", 8080);
        var proxySelector = ProxySelector.of(proxyAddress);

        assertThat(settings.getProxySelector()).isSameAs(HttpClient.Builder.NO_PROXY);
        settings.setProxySelector(proxySelector);
        assertThat(settings.getProxySelector()).isSameAs(proxySelector);
        settings.setProxySelector(null);
        assertThat(settings.getProxySelector()).isEqualTo(HttpClient.Builder.NO_PROXY);

        assertThat(settings.getTimeout()).isEqualTo(Duration.ofSeconds(30));
        settings.setTimeout(Duration.ofMillis(5120));
        assertThat(settings.getTimeout()).isEqualTo(Duration.ofMillis(5120));

        var defaultAuthenticator = Authenticator.getDefault();
        assertThat(settings.getAuthenticator()).isNull();
        settings.setAuthenticator(defaultAuthenticator);
        assertThat(settings.getAuthenticator()).isSameAs(defaultAuthenticator);

        assertThat(settings.isCompressionEnabled()).isTrue();
        settings.setCompressionEnabled(false);
        assertThat(settings.isCompressionEnabled()).isFalse();

        assertThat(settings.isClientReuseEnabled()).isFalse();
        settings.setClientReuseEnabled(true);
        assertThat(settings.isClientReuseEnabled()).isTrue();
        settings.setClientReuseEnabled(false);
        assertThat(settings.isClientReuseEnabled()).isFalse();
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

    @Test
    public void testSystemProperty() {
        assertThat(NetworkSettings.GZIP_PROPERTY_NAME)
                .startsWith("org.shredzone.acme4j")
                .contains("gzip");

        System.clearProperty(NetworkSettings.GZIP_PROPERTY_NAME);
        var settingsNone = new NetworkSettings();
        assertThat(settingsNone.isCompressionEnabled()).isTrue();

        System.setProperty(NetworkSettings.GZIP_PROPERTY_NAME, "true");
        var settingsTrue = new NetworkSettings();
        assertThat(settingsTrue.isCompressionEnabled()).isTrue();

        System.setProperty(NetworkSettings.GZIP_PROPERTY_NAME, "false");
        var settingsFalse = new NetworkSettings();
        assertThat(settingsFalse.isCompressionEnabled()).isFalse();

        System.setProperty(NetworkSettings.GZIP_PROPERTY_NAME, "1234");
        var settingsNonBoolean = new NetworkSettings();
        assertThat(settingsNonBoolean.isCompressionEnabled()).isFalse();
    }

    /**
     * Test that client reuse defaults to false for backward compatibility.
     */
    @Test
    public void testClientReuseDefault() {
        var settings = new NetworkSettings();
        assertThat(settings.isClientReuseEnabled()).isFalse();
    }

    /**
     * Test that equals and hashCode include clientReuse.
     */
    @Test
    public void testClientReuseEqualsAndHashCode() {
        var settings1 = new NetworkSettings();
        var settings2 = new NetworkSettings();
        var settings3 = new NetworkSettings();

        // Same default values should be equal
        assertThat(settings1).isEqualTo(settings2);
        assertThat(settings1.hashCode()).isEqualTo(settings2.hashCode());

        // Different clientReuse should not be equal
        settings3.setClientReuseEnabled(true);
        assertThat(settings1).isNotEqualTo(settings3);
        assertThat(settings1.hashCode()).isNotEqualTo(settings3.hashCode());

        // Same clientReuse should be equal again
        settings1.setClientReuseEnabled(true);
        assertThat(settings1).isEqualTo(settings3);
        assertThat(settings1.hashCode()).isEqualTo(settings3.hashCode());
    }

}
