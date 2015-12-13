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
package org.shredzone.acme4j.provider;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Unit test for {@link LetsEncryptHttpConnector}.
 *
 * @author Richard "Shred" Körber
 */
public class LetsEncryptHttpConnectorTest {

    /**
     * Test if the {@link LetsEncryptAcmeClientProvider#openConnection(URI)} accepts only
     * the Let's Encrypt certificate.
     * <p>
     * This test requires a network connection. It should be excluded from automated
     * builds.
     */
    @Test
    @Category(HttpURLConnection.class)
    public void testCertificate() throws IOException, URISyntaxException {
        LetsEncryptHttpConnector connector = new LetsEncryptHttpConnector();

        try {
            HttpURLConnection goodConn = connector.openConnection(
                            new URI("https://acme-staging.api.letsencrypt.org/directory"));
            assertThat(goodConn, is(instanceOf(HttpsURLConnection.class)));
            goodConn.connect();
        } catch (SSLHandshakeException ex) {
            fail("Connection does not accept Let's Encrypt certificate");
        }

        try {
            HttpURLConnection badConn = connector.openConnection(
                            new URI("https://www.google.com"));
            assertThat(badConn, is(instanceOf(HttpsURLConnection.class)));
            badConn.connect();
            fail("Connection accepts foreign certificate");
        } catch (SSLHandshakeException ex) {
            // expected
        }
    }

    /**
     * Test that the {@link SSLSocketFactory} can be instantiated and is cached.
     */
    @Test
    public void testCreateSocketFactory() throws IOException {
        LetsEncryptHttpConnector connector = new LetsEncryptHttpConnector();

        SSLSocketFactory factory1 = connector.createSocketFactory();
        assertThat(factory1, is(notNullValue()));

        SSLSocketFactory factory2 = connector.createSocketFactory();
        assertThat(factory1, is(sameInstance(factory2)));
    }

}
