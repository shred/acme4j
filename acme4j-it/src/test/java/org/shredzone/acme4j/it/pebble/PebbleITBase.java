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
package org.shredzone.acme4j.it.pebble;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.it.BammBammClient;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Superclass for all Pebble related integration tests.
 * <p>
 * These tests require a running
 * <a href="https://github.com/letsencrypt/pebble">Pebble</a> ACME test server at
 * localhost port 14000. The host and port can be changed via the system property
 * {@code pebbleHost} and {@code pebblePort} respectively.
 * <p>
 * Also, a running pebble-challtestsrv is required to listen on localhost port 8055. The
 * server's base URL can be changed via the system property {@code bammbammUrl}.
 */
public abstract class PebbleITBase {
    private final String pebbleHost = System.getProperty("pebbleHost", "localhost");
    private final int pebblePort = Integer.parseInt(System.getProperty("pebblePort", "14000"));

    private final String bammbammUrl = System.getProperty("bammbammUrl", "http://localhost:8055");

    private BammBammClient bammBammClient;

    private final List<CleanupCallback> cleanup = new ArrayList<>();

    @After
    public void performCleanup() throws Exception {
        for (CleanupCallback callback : cleanup) {
            callback.cleanup();
        }
        cleanup.clear();
    }

    protected void cleanup(CleanupCallback callback) {
        cleanup.add(callback);
    }

    /**
     * @return The {@link URI} of the pebble server to test against.
     */
    protected URI pebbleURI() {
        return URI.create("acme://pebble/" + pebbleHost + ":" + pebblePort);
    }

    /**
     * @return {@link BammBammClient} singleton instance.
     */
    protected BammBammClient getBammBammClient() {
        if (bammBammClient == null) {
            bammBammClient = new BammBammClient(bammbammUrl);
        }
        return bammBammClient;
    }

    /**
     * Creates a fresh key pair.
     *
     * @return Created {@link KeyPair}, guaranteed to be unknown to the Pebble server
     */
    protected KeyPair createKeyPair() {
        return KeyPairUtils.createKeyPair(2048);
    }

    /**
     * Asserts that the given {@link URL} is not {@code null} and refers to the Pebble
     * server.
     *
     * @param url
     *            {@link URL} to assert
     */
    protected void assertIsPebbleUrl(URL url) {
        assertThat(url, not(nullValue()));
        assertThat(url.getProtocol(), is("https"));
        assertThat(url.getHost(), is(pebbleHost));
        assertThat(url.getPort(), is(pebblePort));
        assertThat(url.getPath(), not(emptyOrNullString()));
    }

    /**
     * Safely updates the authorization, catching checked exceptions.
     *
     * @param auth
     *            {@link Authorization} to update
     */
    protected void updateAuth(Authorization auth) {
        try {
            auth.update();
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(auth, ex);
        }
    }

    /**
     * Safely updates the order, catching checked exceptions.
     *
     * @param order
     *            {@link Order} to update
     */
    protected void updateOrder(Order order) {
        try {
            order.update();
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(order, ex);
        }
    }

    @FunctionalInterface
    public static interface CleanupCallback {
        void cleanup() throws Exception;
    }

}
