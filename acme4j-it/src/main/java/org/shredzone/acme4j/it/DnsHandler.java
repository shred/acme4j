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

import java.net.InetAddress;
import java.util.Map;

import org.shredzone.acme4j.it.server.DnsServer;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;

/**
 * Request handler for all {@code dns-01} related requests.
 */
public final class DnsHandler {

    public static final String ADD_A_RECORD = "/dns/add/a/:domain";
    public static final String REMOVE_A_RECORD = "/dns/remove/a/:domain";
    public static final String ADD_TXT_RECORD = "/dns/add/txt/:domain";
    public static final String REMOVE_TXT_RECORD = "/dns/remove/txt/:domain";

    private DnsHandler() {
        // this class cannot be instanciated.
    }

    /**
     * Adds an A Record.
     */
    public static class AddARecord extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String domain = urlParams.get("domain");
            String ip = session.getParameters().get("ip").get(0);

            DnsServer server = BammBamm.instance().getDnsServer();
            server.addARecord(domain, InetAddress.getByName(ip));
        }
    }

    /**
     * Removes an A Record.
     */
    public static class RemoveARecord extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String domain = urlParams.get("domain");

            DnsServer server = BammBamm.instance().getDnsServer();
            server.removeARecord(domain);
        }
    }

    /**
     * Adds a TXT Record.
     */
    public static class AddTxtRecord extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String domain = urlParams.get("domain");
            String txt = session.getParameters().get("txt").get(0);

            DnsServer server = BammBamm.instance().getDnsServer();
            server.addTxtRecord(domain, txt);
        }
    }

    /**
     * Removes a TXT Record.
     */
    public static class RemoveTxtRecord extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String domain = urlParams.get("domain");

            DnsServer server = BammBamm.instance().getDnsServer();
            server.removeTxtRecord(domain);
        }
    }

}
