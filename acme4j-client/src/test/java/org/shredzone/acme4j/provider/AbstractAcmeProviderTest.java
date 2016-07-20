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
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jose4j.json.JsonUtil;
import org.junit.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.OutOfBand01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.DefaultConnection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link AbstractAcmeProvider}.
 *
 * @author Richard "Shred" Körber
 */
public class AbstractAcmeProviderTest {

    /**
     * Test that connect returns a connection.
     */
    @Test
    public void testConnect() {
        final AtomicBoolean invoked = new AtomicBoolean();

        AbstractAcmeProvider provider = new AbstractAcmeProvider() {
            @Override
            public boolean accepts(URI serverUri) {
                throw new UnsupportedOperationException();
            }

            @Override
            public URI resolve(URI serverUri) {
                throw new UnsupportedOperationException();
            }

            @Override
            protected HttpConnector createHttpConnector() {
                invoked.set(true);
                return super.createHttpConnector();
            }
        };

        Connection connection = provider.connect();
        assertThat(connection, not(nullValue()));
        assertThat(connection, instanceOf(DefaultConnection.class));
        assertThat(invoked.get(), is(true));
    }

    /**
     * Verify that the resources directory is read.
     */
    @Test
    public void testResources() throws Exception {
        final URI testServerUri = new URI("http://example.com/acme");
        final URI testResolvedUri = new URI("http://example.com/acme/directory");
        final Connection connection = mock(Connection.class);
        final Session session = mock(Session.class);

        when(connection.sendRequest(testResolvedUri)).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.readJsonResponse()).thenReturn(TestUtils.getJsonAsMap("directory"));

        AbstractAcmeProvider provider = new AbstractAcmeProvider() {
            @Override
            public Connection connect() {
                return connection;
            }

            @Override
            public boolean accepts(URI serverUri) {
                assertThat(serverUri, is(testServerUri));
                return true;
            }

            @Override
            public URI resolve(URI serverUri) {
                assertThat(serverUri, is(testServerUri));
                return testResolvedUri;
            }
        };

        Map<String, Object> map = provider.directory(session, testServerUri);
        assertThat(JsonUtil.toJson(map), sameJSONAs(TestUtils.getJson("directory")));

        verify(connection).sendRequest(testResolvedUri);
        verify(connection).updateSession(any(Session.class));
        verify(connection).readJsonResponse();
        verify(connection).close();
        verifyNoMoreInteractions(connection);
    }

    /**
     * Test that challenges are generated properly.
     */
    @Test
    @SuppressWarnings("deprecation") // must test deprecated challenges
    public void testCreateChallenge() {
        Session session = mock(Session.class);

        AbstractAcmeProvider provider = new AbstractAcmeProvider() {
            @Override
            public boolean accepts(URI serverUri) {
                throw new UnsupportedOperationException();
            }

            @Override
            public URI resolve(URI serverUri) {
                throw new UnsupportedOperationException();
            }
        };

        Challenge c1 = provider.createChallenge(session, Http01Challenge.TYPE);
        assertThat(c1, not(nullValue()));
        assertThat(c1, instanceOf(Http01Challenge.class));

        Challenge c2 = provider.createChallenge(session, Http01Challenge.TYPE);
        assertThat(c2, not(sameInstance(c1)));

        Challenge c3 = provider.createChallenge(session, Dns01Challenge.TYPE);
        assertThat(c3, not(nullValue()));
        assertThat(c3, instanceOf(Dns01Challenge.class));

        Challenge c4 = provider.createChallenge(session, org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE);
        assertThat(c4, not(nullValue()));
        assertThat(c4, instanceOf(org.shredzone.acme4j.challenge.TlsSni01Challenge.class));

        Challenge c5 = provider.createChallenge(session, TlsSni02Challenge.TYPE);
        assertThat(c5, not(nullValue()));
        assertThat(c5, instanceOf(TlsSni02Challenge.class));

        Challenge c6 = provider.createChallenge(session, "foobar-01");
        assertThat(c6, is(nullValue()));

        Challenge c7 = provider.createChallenge(session, OutOfBand01Challenge.TYPE);
        assertThat(c7, not(nullValue()));
        assertThat(c7, instanceOf(OutOfBand01Challenge.class));

        try {
            provider.createChallenge(session, (String) null);
            fail("null was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            provider.createChallenge(session, "");
            fail("empty string was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

}
