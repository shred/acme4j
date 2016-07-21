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
import java.net.HttpURLConnection;
import java.net.URI;

/**
 * A generic HTTP connector. It connects to the given URI with a 10 seconds connection and
 * read timeout.
 * <p>
 * Subclasses may reconfigure the {@link HttpURLConnection} and pin it to a concrete SSL
 * certificate.
 */
public class HttpConnector {

    private static final int TIMEOUT = 10000;

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
        conn.setRequestProperty("User-Agent", "acme4j");
        return conn;
    }

}
