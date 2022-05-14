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
package org.shredzone.acme4j.provider.pebble;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.net.URISyntaxException;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link PebbleAcmeProvider}.
 */
public class PebbleAcmeProviderTest {

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        PebbleAcmeProvider provider = new PebbleAcmeProvider();

        try (AutoCloseableSoftAssertions softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(provider.accepts(new URI("acme://pebble"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/some-host.example.com"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/some-host.example.com:12345"))).isTrue();
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
        PebbleAcmeProvider provider = new PebbleAcmeProvider();

        assertThat(provider.resolve(new URI("acme://pebble")))
                .isEqualTo(url("https://localhost:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/")))
                .isEqualTo(url("https://localhost:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com")))
                .isEqualTo(url("https://pebble.example.com:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com:12345")))
                .isEqualTo(url("https://pebble.example.com:12345/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com:12345/")))
                .isEqualTo(url("https://pebble.example.com:12345/dir"));

        assertThrows(IllegalArgumentException.class, () -> {
            provider.resolve(new URI("acme://pebble/bad.example.com:port"));
        });

        assertThrows(IllegalArgumentException.class, () -> {
            provider.resolve(new URI("acme://pebble/bad.example.com:1234/foo"));
        });
    }

}
