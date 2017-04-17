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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Superclass for all Pebble related integration tests.
 * <p>
 * These tests require a running
 * <a href="https://github.com/letsencrypt/pebble">Pebble</a> ACME test server at
 * localhost port 14000.
 */
public abstract class AbstractPebbleIT {

    private final String pebbleHost = System.getProperty("pebbleHost", "localhost");
    private final int pebblePort = Integer.parseInt(System.getProperty("pebblePort", "14000"));

    /**
     * @return The {@link URI} of the pebble server to test against.
     */
    protected URI pebbleURI() {
        return URI.create("acme://pebble/" + pebbleHost + ":" + pebblePort);
    }

    /**
     * Creates a fresh key pair.
     *
     * @return Created {@link KeyPair}, guaranteed to be unknown to the Pebble server
     */
    protected KeyPair createKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new InternalError(ex);
        }
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
        assertThat(url.getProtocol(), is("http"));
        assertThat(url.getHost(), is(pebbleHost));
        assertThat(url.getPort(), is(pebblePort));
        assertThat(url.getPath(), not(isEmptyOrNullString()));
    }

}
