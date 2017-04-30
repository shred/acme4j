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
package org.shredzone.acme4j.it.server;

import static java.util.Collections.synchronizedMap;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

/**
 * A very simple web server that will answer at the {@code .well-known/acme-challenge}
 * path, returning the challenge to the given token.
 * <p>
 * This server can be used to validate {@code http-01} challenges.
 */
public class HttpServer {
    private static final Logger LOG = LoggerFactory.getLogger(HttpServer.class);

    private static final String TOKEN_PATH = "/.well-known/acme-challenge/";
    private static final Pattern TOKEN_PATTERN = Pattern.compile("^" + Pattern.quote(TOKEN_PATH) + "([^/]+)$");

    private final Map<String, String> tokenMap = synchronizedMap(new HashMap<>());
    private NanoHTTPD server;

    /**
     * Adds a token to the server's well-known challenges. If the token was already set,
     * the challenge will be replaced.
     *
     * @param token
     *            Token the server will respond to
     * @param challenge
     *            Challenge the server will respond with
     */
    public void addToken(String token, String challenge) {
        tokenMap.put(token, challenge);
    }

    /**
     * Removes a token from the server's well-known challenges.
     *
     * @param token
     *            Token to remove
     */
    public void removeToken(String token) {
        tokenMap.remove(token);
    }

    /**
     * Starts the HTTP server.
     *
     * @param port
     *            Port to listen at
     */
    public void start(int port) {
        if (server != null) {
            throw new IllegalStateException("Server is already running");
        }

        server = new NanoHTTPD(port) {
            @Override
            public Response serve(IHTTPSession session) {
                String path = session.getUri().replaceAll("//+", "/");

                Matcher m = TOKEN_PATTERN.matcher(path);
                if (!m.matches()) {
                    return newFixedLengthResponse(Status.NOT_FOUND, "text/plain", "not found: "+ path + "\n");
                }

                String token = m.group(1);
                String content = tokenMap.get(token);

                if (content == null) {
                    LOG.warn("http-01: unknown token " + token);
                    return newFixedLengthResponse(Status.NOT_FOUND, "text/plain", "unknown token: "+ token + "\n");
                }

                LOG.info("http-01: " + token + " -> " + content);
                return newFixedLengthResponse(Status.OK, "text/plain", content);
            }
        };

        try {
            server.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
            LOG.info("http-01 server listening at port {}", port);
        } catch (IOException ex) {
            LOG.error("Failed to start http-01 server", ex);
            server = null;
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Stops the HTTP server.
     */
    public void stop() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }

    /**
     * Checks if the server was started up and is listening to connections.
     */
    public boolean isListening() {
        return server != null && server.wasStarted();
    }

}
