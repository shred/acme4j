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
package org.shredzone.acme4j.provider.letsencrypt;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.TestUtils.url;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;

/**
 * Unit tests for {@link LetsEncryptAcmeProvider}.
 */
public class LetsEncryptAcmeProviderTest {

    private static final String V01_DIRECTORY_URL = "https://acme-v01.api.letsencrypt.org/directory";
    private static final String STAGING_DIRECTORY_URL = "https://acme-staging.api.letsencrypt.org/directory";

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        LetsEncryptAcmeProvider provider = new LetsEncryptAcmeProvider();

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
        LetsEncryptAcmeProvider provider = new LetsEncryptAcmeProvider();

        assertThat(provider.resolve(new URI("acme://letsencrypt.org")), is(url(V01_DIRECTORY_URL)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/")), is(url(V01_DIRECTORY_URL)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/v01")), is(url(V01_DIRECTORY_URL)));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/staging")), is(url(STAGING_DIRECTORY_URL)));

        try {
            provider.resolve(new URI("acme://letsencrypt.org/v99"));
            fail("accepted unknown path");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

}
