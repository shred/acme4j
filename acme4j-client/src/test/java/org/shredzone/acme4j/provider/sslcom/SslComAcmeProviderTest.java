/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2024 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider.sslcom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.net.URISyntaxException;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SslComAcmeProviderTest}.
 */
public class SslComAcmeProviderTest {

    private static final String PRODUCTION_DIRECTORY_URL = "https://acme.ssl.com/sslcom-dv-ecc";
    private static final String STAGING_DIRECTORY_URL = "https://acme-try.ssl.com/sslcom-dv-ecc";

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        var provider = new SslComAcmeProvider();

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(provider.accepts(new URI("acme://ssl.com"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://ssl.com/"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://ssl.com/staging"))).isTrue();
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
        var provider = new SslComAcmeProvider();

        assertThat(provider.resolve(new URI("acme://ssl.com"))).isEqualTo(url(PRODUCTION_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://ssl.com/"))).isEqualTo(url(PRODUCTION_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://ssl.com/staging"))).isEqualTo(url(STAGING_DIRECTORY_URL));

        assertThatIllegalArgumentException().isThrownBy(() -> provider.resolve(new URI("acme://ssl.com/v99")));
    }

}
