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

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Properties;

import org.slf4j.LoggerFactory;

/**
 * A generic HTTP connector. It connects to the given URI with a 10 seconds connection and
 * read timeout.
 * <p>
 * Subclasses may reconfigure the {@link HttpURLConnection} and pin it to a concrete SSL
 * certificate.
 */
public class HttpConnector {

    private static final int TIMEOUT = 10000;
    private static final String USER_AGENT;

    static {
        StringBuilder agent = new StringBuilder("acme4j");

        try (InputStream in = HttpConnector.class.getResourceAsStream("/org/shredzone/acme4j/version.properties")) {
            Properties prop = new Properties();
            prop.load(in);
            agent.append('/').append(prop.getProperty("version"));
        } catch (IOException ex) {
            // Ignore, just don't use a version
            LoggerFactory.getLogger(HttpConnector.class).warn("Could not read library version", ex);
        }

        agent.append(" Java/").append(System.getProperty("java.version"));
        USER_AGENT = agent.toString();
    }

    /**
     * Opens a {@link HttpURLConnection} to the given {@link URI}.
     *
     * @param uri
     *            {@link URI} to connect to
     * @return {@link HttpURLConnection} connected to the {@link URI}
     */
    public HttpURLConnection openConnection(URI uri) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
        conn.setUseCaches(false);
        conn.setRequestProperty("User-Agent", USER_AGENT);
        return conn;
    }

}
