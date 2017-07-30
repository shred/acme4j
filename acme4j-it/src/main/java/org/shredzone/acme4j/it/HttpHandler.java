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
package org.shredzone.acme4j.it;

import java.util.Map;

import org.shredzone.acme4j.it.server.HttpServer;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;

/**
 * Request handler for all {@code http-01} related requests.
 */
public final class HttpHandler {

    public static final String ADD = "/http/add/:token";
    public static final String REMOVE = "/http/remove/:token";

    private HttpHandler() {
        // this class cannot be instanciated.
    }

    /**
     * Adds a HTTP challenge.
     */
    public static class Add extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String token = urlParams.get("token");
            String challenge = session.getParameters().get("challenge").get(0);

            HttpServer server = BammBamm.instance().getHttpServer();
            server.addToken(token, challenge);
        }
    }

    /**
     * Removes a HTTP challenge.
     */
    public static class Remove extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String token = urlParams.get("token");

            HttpServer server = BammBamm.instance().getHttpServer();
            server.removeToken(token);
        }
    }

}
