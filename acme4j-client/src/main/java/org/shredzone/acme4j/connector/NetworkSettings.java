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

import java.net.Authenticator;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Contains network settings to be used for network connections.
 *
 * @since 2.8
 */
public class NetworkSettings {

    /**
     * Name of the system property to control GZIP compression. Expects a boolean value.
     */
    public static final String GZIP_PROPERTY_NAME = "org.shredzone.acme4j.gzip_compression";

    private ProxySelector proxySelector = HttpClient.Builder.NO_PROXY;
    private Duration timeout = Duration.ofSeconds(30);
    private @Nullable Authenticator authenticator = null;
    private boolean compression = true;

    public NetworkSettings() {
        try {
            Optional.ofNullable(System.getProperty(GZIP_PROPERTY_NAME))
                    .map(Boolean::parseBoolean)
                    .ifPresent(val -> compression = val);
        } catch (Exception ex) {
            // Ignore a broken property name or a SecurityException
            LoggerFactory.getLogger(NetworkSettings.class)
                    .warn("Could not read system property: {}", GZIP_PROPERTY_NAME, ex);
        }
    }

    /**
     * Gets the {@link ProxySelector} to be used for connections.
     *
     * @since 3.0.0
     */
    public ProxySelector getProxySelector() {
        return proxySelector;
    }

    /**
     * Sets a {@link ProxySelector} that is to be used for all connections. If
     * {@code null}, {@link HttpClient.Builder#NO_PROXY} is used, which is also the
     * default.
     *
     * @since 3.0.0
     */
    public void setProxySelector(@Nullable ProxySelector proxySelector) {
        this.proxySelector = proxySelector != null ? proxySelector : HttpClient.Builder.NO_PROXY;
    }

    /**
     * Gets the {@link Authenticator} to be used, or {@code null} if none is to be set.
     *
     * @since 3.0.0
     */
    public @Nullable Authenticator getAuthenticator() {
        return authenticator;
    }

    /**
     * Sets an {@link Authenticator} to be used if HTTP authentication is needed (e.g.
     * by a proxy). {@code null} means that no authenticator shall be set.
     *
     * @since 3.0.0
     */
    public void setAuthenticator(@Nullable Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Gets the current network timeout.
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Sets the network timeout to be used for connections. Defaults to 10 seconds.
     *
     * @param timeout
     *         Network timeout {@link Duration}
     */
    public void setTimeout(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("Timeout must be positive");
        }

        this.timeout = timeout;
    }

    /**
     * Checks if HTTP compression is enabled.
     *
     * @since 3.0.0
     */
    public boolean isCompressionEnabled() {
        return compression;
    }

    /**
     * Sets if HTTP compression is enabled. It is enabled by default, but can be
     * disabled e.g. for debugging purposes.
     * <p>
     * acme4j gzip compression can also be controlled via the {@value #GZIP_PROPERTY_NAME}
     * system property.
     *
     * @since 3.0.0
     */
    public void setCompressionEnabled(boolean compression) {
        this.compression = compression;
    }

}
