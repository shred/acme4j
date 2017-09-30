/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.connector;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.util.ServiceLoader;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Session#provider()}. Requires that both enclosed
 * {@link AcmeProvider} implementations are registered via Java's {@link ServiceLoader}
 * API when the test is run.
 */
public class SessionProviderTest {

    private KeyPair keyPair;

    @Before
    public void setup() throws IOException {
        keyPair = TestUtils.createKeyPair();
    }

    /**
     * There are no testing providers accepting {@code acme://example.org}. Test that
     * connecting to this URI will result in an {@link IllegalArgumentException}.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNone() throws Exception {
        new Session(new URI("acme://example.org"), keyPair).provider();
    }

    /**
     * Test that connecting to an acme URI will return an {@link AcmeClient} via
     * the correct {@link AcmeProvider}, and that the result is cached.
     */
    @Test
    public void testConnectURI() throws Exception {
        Session session = new Session(new URI("acme://example.com"), keyPair);

        AcmeProvider provider = session.provider();
        assertThat(provider, is(instanceOf(Provider1.class)));

        AcmeProvider provider2 = session.provider();
        assertThat(provider2, is(instanceOf(Provider1.class)));
        assertThat(provider2, is(sameInstance(provider)));
    }

    /**
     * There are two testing providers accepting {@code acme://example.net}. Test that
     * connecting to this URI will result in an {@link IllegalArgumentException}.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testDuplicate() throws Exception {
        new Session(new URI("acme://example.net"), keyPair).provider();
    }

    public static class Provider1 implements AcmeProvider {
        @Override
        public boolean accepts(URI serverUri) {
            return "acme".equals(serverUri.getScheme())
                    && ("example.com".equals(serverUri.getHost())
                           || "example.net".equals(serverUri.getHost()));
        }

        @Override
        public Connection connect() {
            throw new UnsupportedOperationException();
        }

        @Override
        public URI resolve(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JSON directory(Session session, URI serverUri) throws AcmeException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Challenge createChallenge(Session session, String type) {
            throw new UnsupportedOperationException();
        }
    }

    public static class Provider2 implements AcmeProvider {
        @Override
        public boolean accepts(URI serverUri) {
            return "acme".equals(serverUri.getScheme())
                    && "example.net".equals(serverUri.getHost());
        }

        @Override
        public Connection connect() {
            throw new UnsupportedOperationException();
        }

        @Override
        public URI resolve(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JSON directory(Session session, URI serverUri) throws AcmeException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Challenge createChallenge(Session session, String type) {
            throw new UnsupportedOperationException();
        }
    }

}