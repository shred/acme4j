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

import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Properties;

import org.slf4j.LoggerFactory;

/**
 * A generic HTTP connector. It creates {@link HttpClient.Builder} and
 * {@link HttpRequest.Builder} that can be individually customized according to the needs
 * of the CA.
 *
 * @since 3.0.0
 */
public class HttpConnector {
    private static final String USER_AGENT;

    private final NetworkSettings networkSettings;

    static {
        var agent = new StringBuilder("acme4j");

        try (var in = HttpConnector.class.getResourceAsStream("/org/shredzone/acme4j/version.properties")) {
            var prop = new Properties();
            prop.load(in);
            agent.append('/').append(prop.getProperty("version"));
        } catch (Exception ex) {
            // Ignore, just don't use a version
            LoggerFactory.getLogger(HttpConnector.class).warn("Could not read library version", ex);
        }

        agent.append(" Java/").append(System.getProperty("java.version"));
        USER_AGENT = agent.toString();
    }

    /**
     * Returns the default User-Agent to be used.
     *
     * @return User-Agent
     */
    public static String defaultUserAgent() {
        return USER_AGENT;
    }

    /**
     * Creates a new {@link HttpConnector} that is using the given
     * {@link NetworkSettings}.
     */
    public HttpConnector(NetworkSettings networkSettings) {
        this.networkSettings = networkSettings;
    }

    /**
     * Creates a new {@link HttpRequest.Builder} that is preconfigured and bound to the
     * given URL. Subclasses can override this method to extend the configuration, or
     * create a different builder.
     *
     * @param url
     *            {@link URL} to connect to
     * @return {@link HttpRequest.Builder} connected to the {@link URL}
     */
    public HttpRequest.Builder createRequestBuilder(URL url) {
        try {
            return HttpRequest.newBuilder(url.toURI())
                    .header("User-Agent", USER_AGENT)
                    .timeout(networkSettings.getTimeout());
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid URL", ex);
        }
    }

    /**
     * Creates a new {@link HttpClient.Builder}.
     * <p>
     * The {@link HttpClient.Builder} is already preconfigured with a reasonable timeout,
     * the proxy settings, authenticator, and that it follows normal redirects.
     * Subclasses can override this method to extend the configuration, or to create a
     * different builder.
     */
    public HttpClient.Builder createClientBuilder() {
        var builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(networkSettings.getTimeout())
                .proxy(networkSettings.getProxySelector());

        if (networkSettings.getAuthenticator() != null) {
            builder.authenticator(networkSettings.getAuthenticator());
        }

        return builder;
    }

}
