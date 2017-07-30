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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * A very simple and very stupid DNS server. It just responds to TXT and A queries of the
 * given domains, and refuses to answer anything else.
 * <p>
 * This server can be used to validate {@code dns-01} challenges, and to direct other
 * challenges to the mock servers.
 */
public class DnsServer {
    private static final Logger LOG = LoggerFactory.getLogger(DnsServer.class);
    private static final int UDP_SIZE = 512;
    private static final long TTL = 300L;

    private final Map<String, String> txtRecords = synchronizedMap(new HashMap<>());
    private final Map<String, InetAddress> aRecords = synchronizedMap(new HashMap<>());
    private Thread thread = null;
    private volatile boolean running = false;
    private volatile boolean listening = false;

    /**
     * Adds a TXT record to the DNS server. If the domain already has a TXT record
     * attached, it will be replaced.
     *
     * @param domain
     *            Domain to attach the TXT record to
     * @param txt
     *            TXT record to attach
     */
    public void addTxtRecord(String domain, String txt) {
        txtRecords.put(domain.replaceAll("\\.$", ""), txt);
    }

    /**
     * Removes a TXT record from the domain.
     *
     * @param domain
     *            Domain to remove the TXT record from
     */
    public void removeTxtRecord(String domain) {
        txtRecords.remove(domain);
    }

    /**
     * Adds an A record to the DNS server. If the domain already has an A record attached,
     * it will be replaced.
     *
     * @param domain
     *            Domain to attach the A record to
     * @param ip
     *            Target IP address
     */
    public void addARecord(String domain, InetAddress ip) {
        if (!(ip instanceof Inet4Address)) {
            throw new IllegalArgumentException("must be an IPv4 address");
        }
        aRecords.put(domain.replaceAll("\\.$", ""), ip);
    }

    /**
     * Removes an A record from the domain.
     *
     * @param domain
     *            Domain to remove the A record from
     */
    public void removeARecord(String domain) {
        aRecords.remove(domain);
    }

    /**
     * Starts the DNS server.
     *
     * @param port
     *            Port to listen to
     */
    public void start(int port) {
        if (thread != null) {
            throw new IllegalStateException("Server is already running");
        }

        running = true;
        thread = new Thread(() -> serveUDP(port));
        thread.setName("DNS server");
        thread.start();
        LOG.info("dns-01 server listening at port {}", port);
    }

    /**
     * Stops the DNS server.
     */
    public void stop() {
        if (thread != null) {
            running = false;
            thread.interrupt();
            thread = null;
        }
    }

    /**
     * Checks if the server was started up and is listening to connections.
     */
    public boolean isListening() {
        return listening;
    }

    /**
     * Opens an UDP socket and processes incoming messages.
     *
     * @param port
     *            Port to listen at
     */
    private void serveUDP(int port) {
        try (DatagramSocket sock = new DatagramSocket(port)) {
            listening = true;
            while (running) {
                process(sock);
            }
            listening = false;
        } catch (IOException ex) {
            LOG.error("Failed to open UDP socket", ex);
        }
    }

    /**
     * Processes a DNS query.
     *
     * @param sock
     *            Socket to listen to
     */
    private void process(DatagramSocket sock) {
        try {
            byte[] in = new byte[UDP_SIZE];

            // Read the question
            DatagramPacket indp = new DatagramPacket(in, UDP_SIZE);
            indp.setLength(UDP_SIZE);
            sock.receive(indp);
            Message msg = new Message(in);
            Header header = msg.getHeader();

            Record question = msg.getQuestion();

            // Prepare a response
            Message response = new Message(header.getID());
            response.getHeader().setFlag(Flags.QR);
            response.addRecord(question, Section.QUESTION);

            Name name = question.getName();
            boolean hasRecords = false;

            String txt = txtRecords.get(name.toString(true));
            if (question.getType() == Type.TXT && txt != null) {
                response.addRecord(new TXTRecord(name, DClass.IN, TTL, txt), Section.ANSWER);
                hasRecords = true;
                LOG.info("dns-01: {} {} IN TXT \"{}\"", name, TTL, txt);
            }

            InetAddress a = aRecords.get(name.toString(true));
            if (question.getType() == Type.A && a != null) {
                response.addRecord(new ARecord(name, DClass.IN, TTL, a), Section.ANSWER);
                hasRecords = true;
                LOG.info("dns-01: {} {} IN A {}", name, TTL, a.getHostAddress());
            }

            if (!hasRecords) {
                response.getHeader().setRcode(Rcode.NXDOMAIN);
                LOG.warn("dns-01: Cannot answer: {}", question);
            }

            // Send the response
            byte[] resp = response.toWire();
            DatagramPacket outdp = new DatagramPacket(resp, resp.length, indp.getAddress(), indp.getPort());
            sock.send(outdp);
        } catch (Exception ex) {
            LOG.error("Failed to process query", ex);
        }
    }

}
