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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.net.URI;
import java.net.URL;
import java.util.ServiceLoader;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Unit tests for {@link Session#provider()}. Requires that both enclosed
 * {@link AcmeProvider} implementations are registered via Java's {@link ServiceLoader}
 * API when the test is run.
 */
public class SessionProviderTest {

    /**
     * There are no testing providers accepting {@code acme://example.org}. Test that
     * connecting to this URI will result in an {@link IllegalArgumentException}.
     */
    @Test
    public void testNone() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new Session(new URI("acme://example.org")).provider())
                .withMessage("No ACME provider found for acme://example.org");
    }

    /**
     * Test that connecting to an acme URI will return an {@link AcmeProvider}, and that
     * the result is cached.
     */
    @Test
    public void testConnectURI() throws Exception {
        var session = new Session(new URI("acme://example.com"));

        var provider = session.provider();
        assertThat(provider).isInstanceOf(Provider1.class);

        var provider2 = session.provider();
        assertThat(provider2).isInstanceOf(Provider1.class);
        assertThat(provider2).isSameAs(provider);
    }

    /**
     * There are two testing providers accepting {@code acme://example.net}. Test that
     * connecting to this URI will result in an {@link IllegalArgumentException}.
     */
    @Test
    public void testDuplicate() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new Session(new URI("acme://example.net")).provider())
                .withMessage("Both ACME providers Provider1 and Provider2 accept" +
                        " acme://example.net. Please check your classpath.");
    }

    public static class Provider1 implements AcmeProvider {
        @Override
        public boolean accepts(URI serverUri) {
            return "acme".equals(serverUri.getScheme())
                    && ("example.com".equals(serverUri.getHost())
                           || "example.net".equals(serverUri.getHost()));
        }

        @Override
        public Connection connect(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public URL resolve(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JSON directory(Session session, URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Challenge createChallenge(Login login, JSON data) {
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
        public Connection connect(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public URL resolve(URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JSON directory(Session session, URI serverUri) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Challenge createChallenge(Login login, JSON data) {
            throw new UnsupportedOperationException();
        }
    }

}