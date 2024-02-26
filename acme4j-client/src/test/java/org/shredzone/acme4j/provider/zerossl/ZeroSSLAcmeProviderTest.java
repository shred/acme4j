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
package org.shredzone.acme4j.provider.zerossl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.net.URISyntaxException;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ZeroSSLAcmeProvider}.
 */
public class ZeroSSLAcmeProviderTest {

    private static final String V02_DIRECTORY_URL = "https://acme.zerossl.com/v2/DV90";

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        var provider = new ZeroSSLAcmeProvider();

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(provider.accepts(new URI("acme://zerossl.com"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://zerossl.com/"))).isTrue();
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
        var provider = new ZeroSSLAcmeProvider();

        assertThat(provider.resolve(new URI("acme://zerossl.com"))).isEqualTo(url(V02_DIRECTORY_URL));
        assertThat(provider.resolve(new URI("acme://zerossl.com/"))).isEqualTo(url(V02_DIRECTORY_URL));

        assertThrows(IllegalArgumentException.class, () -> provider.resolve(new URI("acme://zerossl.com/v99")));
    }

}
