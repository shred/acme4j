/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider.pebble;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.regex.Pattern;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;

/**
 * An {@link AcmeProvider} for <em>Pebble</em>.
 * <p>
 * <a href="https://github.com/letsencrypt/pebble">Pebble</a> is a small ACME test server.
 * This provider can be used to connect to an instance of a Pebble server.
 * <p>
 * {@code "acme://pebble"} connects to a Pebble server running on localhost and listening
 * on the standard port 14000. Using {@code "acme://pebble/other-host:12345"}, it is
 * possible to connect to an external Pebble server on the given {@code other-host} and
 * port. The port is optional, and if omitted, the standard port is used.
 */
public class PebbleAcmeProvider extends AbstractAcmeProvider {

    private static final Pattern HOST_PATTERN = Pattern.compile("^/([^:/]+)(?:\\:(\\d+))?/?$");

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme()) && "pebble".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        try {
            var path = serverUri.getPath();

            var baseUrl = new URL("https://localhost:14000/dir");

            if (path != null && !path.isEmpty() && !"/".equals(path)) {
                baseUrl = parsePath(path);
            }

            return baseUrl;
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Bad server URI " + serverUri, ex);
        }
    }

    /**
     * Parses the server URI path and returns the server's base URL.
     *
     * @param path
     *            server URI path
     * @return URL of the server's base
     */
    private URL parsePath(String path) throws MalformedURLException {
        var m = HOST_PATTERN.matcher(path);
        if (m.matches()) {
            var host = m.group(1);
            var port = 14000;
            if (m.group(2) != null) {
                port = Integer.parseInt(m.group(2));
            }
            return new URL("https", host, port, "/dir");
        } else {
            throw new IllegalArgumentException("Invalid Pebble host/port: " + path);
        }
    }

    @Override
    protected HttpConnector createHttpConnector(NetworkSettings settings) {
        return new PebbleHttpConnector(settings);
    }

}
