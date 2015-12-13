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
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;

/**
 * Unit tests for {@link GenericAcmeClientProvider}.
 *
 * @author Richard "Shred" Körber
 */
public class GenericAcmeClientProviderTest {

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        GenericAcmeClientProvider provider = new GenericAcmeClientProvider();

        assertThat(provider.accepts(new URI("http://example.com/acme")), is(true));
        assertThat(provider.accepts(new URI("https://example.com/acme")), is(true));
        assertThat(provider.accepts(new URI("acme://example.com")), is(false));
    }

    /**
     * Test if the provider resolves the URI correctly.
     */
    @Test
    public void testResolve() throws URISyntaxException {
        URI serverUri = new URI("http://example.com/acme");

        GenericAcmeClientProvider provider = new GenericAcmeClientProvider();

        URI resolvedUri = provider.resolve(serverUri);
        assertThat(resolvedUri, is(equalTo(serverUri)));
    }

}
