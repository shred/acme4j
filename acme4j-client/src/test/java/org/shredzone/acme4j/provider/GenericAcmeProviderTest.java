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

import static org.assertj.core.api.Assertions.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.DEFAULT_NETWORK_SETTINGS;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.connector.DefaultConnection;

/**
 * Unit tests for {@link GenericAcmeProvider}.
 */
public class GenericAcmeProviderTest {

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        var provider = new GenericAcmeProvider();

        assertThat(provider.accepts(new URI("http://example.com/acme"))).isTrue();
        assertThat(provider.accepts(new URI("https://example.com/acme"))).isTrue();
        assertThat(provider.accepts(new URI("acme://example.com"))).isFalse();
    }

    /**
     * Test if the provider resolves the URI correctly.
     */
    @Test
    public void testResolve() throws URISyntaxException {
        var serverUri = new URI("http://example.com/acme");

        var provider = new GenericAcmeProvider();

        var resolvedUrl = provider.resolve(serverUri);
        assertThat(resolvedUrl.toString()).isEqualTo(serverUri.toString());

        var connection = provider.connect(serverUri, DEFAULT_NETWORK_SETTINGS);
        assertThat(connection).isInstanceOf(DefaultConnection.class);
    }

}
