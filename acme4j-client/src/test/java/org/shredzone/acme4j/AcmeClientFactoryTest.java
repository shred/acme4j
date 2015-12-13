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
package org.shredzone.acme4j;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ServiceLoader;

import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeClientProvider;

/**
 * Unit tests for {@link AcmeClientFactory}. Requires that both enclosed
 * {@link AcmeClientProvider} implementations are registered via Java's
 * {@link ServiceLoader} API when the test is run.
 *
 * @author Richard "Shred" Körber
 */
public class AcmeClientFactoryTest {

    private static final AcmeClient DUMMY_CLIENT = mock(AcmeClient.class);

    /**
     * Test that connecting to an acme URI will return an {@link AcmeClient} via
     * the correct {@link AcmeClientProvider}.
     */
    @Test
    public void testConnectURI() throws URISyntaxException, AcmeException {
        AcmeClient client = AcmeClientFactory.connect(new URI("acme://example.com"));
        assertThat(client, is(sameInstance(DUMMY_CLIENT)));
    }

    /**
     * There are no testing providers accepting {@code acme://example.org}. Test that
     * connecting to this URI will result in an {@link AcmeException}.
     */
    @Test(expected = AcmeException.class)
    public void testNone() throws URISyntaxException, AcmeException {
        AcmeClientFactory.connect(new URI("acme://example.org"));
    }

    /**
     * There are two testing providers accepting {@code acme://example.net}. Test that
     * connecting to this URI will result in an {@link AcmeException}.
     */
    @Test(expected = AcmeException.class)
    public void testDuplicate() throws URISyntaxException, AcmeException {
        AcmeClientFactory.connect(new URI("acme://example.net"));
    }

    public static class Provider1 implements AcmeClientProvider {
        @Override
        public boolean accepts(URI serverUri) {
            return "acme".equals(serverUri.getScheme())
                    && ("example.com".equals(serverUri.getHost())
                            || "example.net".equals(serverUri.getHost()));
        }

        @Override
        public AcmeClient connect(URI serverUri) {
            assertThat(serverUri.toString(), is("acme://example.com"));
            return DUMMY_CLIENT;
        }

        @Override
        public <T extends Challenge> T createChallenge(String type) {
            fail("not supposed to be invoked");
            return null;
        }

        @Override
        public HttpURLConnection openConnection(URI uri) throws IOException {
            fail("not supposed to be invoked");
            return null;
        }
    }

    public static class Provider2 implements AcmeClientProvider {
        @Override
        public boolean accepts(URI serverUri) {
            return "acme".equals(serverUri.getScheme())
                    && "example.net".equals(serverUri.getHost());
        }

        @Override
        public AcmeClient connect(URI serverUri) {
            fail("Wrong AcmeClientProvider was invoked");
            return null;
        }

        @Override
        public <T extends Challenge> T createChallenge(String type) {
            fail("not supposed to be invoked");
            return null;
        }

        @Override
        public HttpURLConnection openConnection(URI uri) throws IOException {
            fail("not supposed to be invoked");
            return null;
        }
    }

}
