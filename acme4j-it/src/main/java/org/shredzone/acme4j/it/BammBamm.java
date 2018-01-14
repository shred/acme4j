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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ResourceBundle;

import org.shredzone.acme4j.it.server.DnsServer;
import org.shredzone.acme4j.it.server.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.router.RouterNanoHTTPD;

/**
 * A mock server to test Pebble. It provides a HTTP server and DNS server. The servers can
 * be configured remotely via simple HTTP POST requests.
 * <p>
 * <em>WARNING:</em> This is a very simple server that is only meant to be used for
 * integration tests. Do not use in the outside world!
 */
public class BammBamm {
    private static final Logger LOG = LoggerFactory.getLogger(BammBamm.class);

    private static final BammBamm INSTANCE = new BammBamm();

    private final int appPort;
    private final int httpPort;
    private final int dnsPort;
    private final AppServer appServer;
    private final DnsServer dnsServer;
    private final HttpServer httpServer;

    private BammBamm() {
        ResourceBundle bundle = ResourceBundle.getBundle("bammbamm");
        appPort = Integer.parseInt(bundle.getString("app.port"));
        dnsPort = Integer.parseInt(bundle.getString("dns.port"));
        httpPort = Integer.parseInt(bundle.getString("http.port"));

        dnsServer = new DnsServer();
        httpServer = new HttpServer();
        appServer = new AppServer(appPort);
    }

    /**
     * Retrieves the singleton instance of {@link BammBamm}.
     *
     * @return {@link BammBamm} singleton instance
     */
    public static BammBamm instance() {
        return INSTANCE;
    }

    /**
     * Returns the {@link DnsServer} instance.
     */
    public DnsServer getDnsServer() {
        return dnsServer;
    }

    /**
     * Returns the {@link HttpServer} instance.
     */
    public HttpServer getHttpServer() {
        return httpServer;
    }

    /**
     * Starts the servers.
     */
    public void start() {
        dnsServer.start(dnsPort);
        httpServer.start(httpPort);

        try {
            appServer.start(NanoHTTPD.SOCKET_READ_TIMEOUT, true);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }

        LOG.info("Bammbamm running, listening on port {}", appServer.getListeningPort());
    }

    /**
     * Stops the servers.
     */
    public void stop() {
        appServer.stop();
        httpServer.stop();
        dnsServer.stop();

        LOG.info("Bammbamm was stopped.");
    }

    /**
     * App server with all predefined routes.
     */
    private static class AppServer extends RouterNanoHTTPD {
        public AppServer(int port) {
            super(port);
            super.addMappings();

            addRoute(DnsHandler.ADD_A_RECORD, DnsHandler.AddARecord.class);
            addRoute(DnsHandler.REMOVE_A_RECORD, DnsHandler.RemoveARecord.class);
            addRoute(DnsHandler.ADD_TXT_RECORD, DnsHandler.AddTxtRecord.class);
            addRoute(DnsHandler.REMOVE_TXT_RECORD, DnsHandler.RemoveTxtRecord.class);

            addRoute(HttpHandler.ADD, HttpHandler.Add.class);
            addRoute(HttpHandler.REMOVE, HttpHandler.Remove.class);
        }
    }

    /**
     * Start bammbamm. It runs until the Java process is stopped.
     *
     * @param args
     *            Command line arguments
     */
    public static void main(String[] args) {
        BammBamm.instance().start();
    }

}
