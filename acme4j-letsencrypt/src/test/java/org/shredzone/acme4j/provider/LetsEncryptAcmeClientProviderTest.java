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
 * Unit tests for {@link LetsEncryptAcmeClientProvider}.
 *
 * @author Richard "Shred" Körber
 */
public class LetsEncryptAcmeClientProviderTest {

    private static final String V01_DIRECTORY_URI = "https://acme-v01.api.letsencrypt.org/directory";
    private static final String STAGING_DIRECTORY_URI = "https://acme-staging.api.letsencrypt.org/directory";

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        LetsEncryptAcmeClientProvider provider = new LetsEncryptAcmeClientProvider();

        assertThat(provider.accepts(new URI("acme://letsencrypt.org")), is(true));
        assertThat(provider.accepts(new URI("acme://letsencrypt.org/")), is(true));
        assertThat(provider.accepts(new URI("acme://letsencrypt.org/staging")), is(true));
        assertThat(provider.accepts(new URI("acme://letsencrypt.org/v01")), is(true));
        assertThat(provider.accepts(new URI("acme://example.com")), is(false));
        assertThat(provider.accepts(new URI("http://example.com/acme")), is(false));
        assertThat(provider.accepts(new URI("https://example.com/acme")), is(false));
    }

    /**
     * Test if acme URIs are properly resolved.
     */
    @Test
    public void testResolve() throws URISyntaxException {
        LetsEncryptAcmeClientProvider provider = new LetsEncryptAcmeClientProvider();

        assertThat(provider.resolve(new URI("acme://letsencrypt.org")), is(new URI(V01_DIRECTORY_URI)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/")), is(new URI(V01_DIRECTORY_URI)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/v01")), is(new URI(V01_DIRECTORY_URI)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/staging")), is(new URI(STAGING_DIRECTORY_URI)));

        try {
            provider.resolve(new URI("acme://letsencrypt.org/v99"));
            fail("accepted unknown path");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

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
        LetsEncryptAcmeClientProvider provider = new LetsEncryptAcmeClientProvider();

        try {
            HttpURLConnection goodConn = provider.openConnection(
                            new URI("https://acme-staging.api.letsencrypt.org/directory"));
            assertThat(goodConn, is(instanceOf(HttpsURLConnection.class)));
            goodConn.connect();
        } catch (SSLHandshakeException ex) {
            fail("Connection does not accept Let's Encrypt certificate");
        }

        try {
            HttpURLConnection badConn = provider.openConnection(
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
        LetsEncryptAcmeClientProvider provider = new LetsEncryptAcmeClientProvider();

        SSLSocketFactory factory1 = provider.createSocketFactory();
        assertThat(factory1, is(notNullValue()));

        SSLSocketFactory factory2 = provider.createSocketFactory();
        assertThat(factory1, is(sameInstance(factory2)));
    }

}
