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
package org.shredzone.acme4j.impl;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeClientProvider;

/**
 * Unit tests for {@link GenericAcmeClient}.
 *
 * @author Richard "Shred" Körber
 */
public class GenericAcmeClientTest {

    private AcmeClientProvider mockProvider;
    private URI directoryUri;

    @Before
    public void setup() throws URISyntaxException {
        mockProvider = mock(AcmeClientProvider.class);
        directoryUri = new URI("http://example.com/acme");
    }

    /**
     * Test if challenges are correctly created via provider.
     */
    @Test
    public void testCreateChallenge() {
        HttpChallenge mockChallenge = mock(HttpChallenge.class);
        when(mockProvider.createChallenge(HttpChallenge.TYPE)).thenReturn(mockChallenge);

        GenericAcmeClient client = new GenericAcmeClient(mockProvider, directoryUri);
        Challenge challenge = client.createChallenge(HttpChallenge.TYPE);

        assertThat(challenge, is(instanceOf(HttpChallenge.class)));
        assertThat(challenge, is(sameInstance((Challenge) mockChallenge)));

        verify(mockProvider).createChallenge(HttpChallenge.TYPE);
    }

    /**
     * Test if connections are correctly created via provider.
     */
    @Test
    public void testCreateConnection() {
        Connection mockConnection = mock(Connection.class);
        when(mockProvider.createConnection()).thenReturn(mockConnection);

        GenericAcmeClient client = new GenericAcmeClient(mockProvider, directoryUri);
        Connection connection = client.createConnection();

        assertThat(connection, is(sameInstance(mockConnection)));

        verify(mockProvider).createConnection();
    }

    /**
     * Test that the directory is properly read and cached.
     */
    @Test
    public void testResourceUri() throws AcmeException, URISyntaxException {
        Map<Resource, URI> directoryMap = new HashMap<Resource, URI>();
        directoryMap.put(Resource.NEW_AUTHZ, new URI("http://example.com/acme/new-authz"));
        directoryMap.put(Resource.NEW_CERT, new URI("http://example.com/acme/new-cert"));

        Connection mockConnection = mock(Connection.class);
        when(mockConnection.readDirectory()).thenReturn(directoryMap);

        when(mockProvider.createConnection()).thenReturn(mockConnection);

        GenericAcmeClient client = new GenericAcmeClient(mockProvider, directoryUri);
        assertThat(client.resourceUri(Resource.NEW_AUTHZ), is(new URI("http://example.com/acme/new-authz")));
        assertThat(client.resourceUri(Resource.NEW_CERT), is(new URI("http://example.com/acme/new-cert")));
        assertThat(client.resourceUri(Resource.NEW_REG), is(nullValue()));

        // Make sure directory is only read once!
        verify(mockConnection, times(1)).sendRequest(directoryUri);
        verify(mockConnection, times(1)).readDirectory();

        verify(mockProvider).createConnection();
    }

}
