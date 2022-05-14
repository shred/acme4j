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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.net.URISyntaxException;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link LetsEncryptAcmeProvider}.
 */
public class LetsEncryptAcmeProviderTest {

    private static final String V02_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
    private static final String STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        LetsEncryptAcmeProvider provider = new LetsEncryptAcmeProvider();

        try (AutoCloseableSoftAssertions softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(provider.accepts(new URI("acme://letsencrypt.org"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://letsencrypt.org/"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://letsencrypt.org/staging"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://letsencrypt.org/v02"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://example.com"))).isFalse();
            softly.assertThat(provider.accepts(new URI("http://example.com/acme"))).isFalse();
            softly.assertThat(provider.accepts(new URI("https://example.com/acme"))).isFalse();
        }
    }

    /**
     * Test if acme URIs are properly resolved.
     */
    @Test
    public void testResolve() throws URISyntaxException {
        LetsEncryptAcmeProvider provider = new LetsEncryptAcmeProvider();

        assertThat(provider.resolve(new URI("acme://letsencrypt.org"))).isEqualTo(url(V02_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/"))).isEqualTo(url(V02_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/v02"))).isEqualTo(url(V02_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://letsencrypt.org/staging"))).isEqualTo(url(STAGING_DIRECTORY_URL));

        assertThrows(IllegalArgumentException.class, () -> {
            provider.resolve(new URI("acme://letsencrypt.org/v99"));
        });
    }

}
