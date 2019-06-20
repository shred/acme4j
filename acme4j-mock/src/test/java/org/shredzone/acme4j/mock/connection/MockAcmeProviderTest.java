/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.function.Function;

import org.junit.Test;
import org.shredzone.acme4j.connector.Connection;

/**
 * Unit tests for {@link MockAcmeProvider}.
 */
public class MockAcmeProviderTest {

    /**
     * Test that the {@link MockAcmeProvider#MOCK_URI} constant is valid and unchanged.
     */
    @Test
    public void testURI() {
        assertThat(MockAcmeProvider.MOCK_URI, is(URI.create("acme://mock/")));
    }

    /**
     * Test {@link MockAcmeProvider#accepts(URI)}.
     */
    @Test
    public void testAccept() throws MalformedURLException {
        URL directoryUrl = new URL("https://acme.test/directory");
        Function<URI, Connection> factory = u -> mock(Connection.class);

        MockAcmeProvider provider = new MockAcmeProvider(directoryUrl, factory);

        assertThat(provider.accepts(MockAcmeProvider.MOCK_URI), is(true));
        assertThat(provider.accepts(URI.create("acme://pebble")), is(false));
        assertThat(provider.accepts(URI.create("http://localhost/dir")), is(false));
    }

    /**
     * Test {@link MockAcmeProvider#resolve(URI)}.
     */
    @Test
    public void testResolve() throws MalformedURLException {
        URL directoryUrl = new URL("https://acme.test/directory");
        Function<URI, Connection> factory = u -> mock(Connection.class);

        MockAcmeProvider provider = new MockAcmeProvider(directoryUrl, factory);

        assertThat(provider.resolve(MockAcmeProvider.MOCK_URI), is(directoryUrl));
    }

    /**
     * Test {@link MockAcmeProvider#connect(URI)}.
     */
    @Test
    public void testConnect() throws MalformedURLException {
        URL directoryUrl = new URL("https://acme.test/directory");
        Function<URI, Connection> factory = u -> mock(Connection.class);

        MockAcmeProvider provider = new MockAcmeProvider(directoryUrl, factory);

        Connection conn = provider.connect(MockAcmeProvider.MOCK_URI);
        assertThat(conn, not(nullValue()));
        assertThat(conn, is(instanceOf(Connection.class)));
    }

}
