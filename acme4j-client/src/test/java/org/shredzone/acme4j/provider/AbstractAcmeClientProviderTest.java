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

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;
import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.ProofOfPossession01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;

/**
 * Unit tests for {@link AbstractAcmeClientProvider}.
 *
 * @author Richard "Shred" Körber
 */
public class AbstractAcmeClientProviderTest {

    /**
     * Test if an {@link AcmeClient} is properly generated and configurated.
     */
    @Test
    public void testResolveAndConnect() throws URISyntaxException {
        final URI testAcmeUri = new URI("acme://example.com");
        final URI testDirectoryUri = new URI("http://example.com/acme");

        AbstractAcmeClientProvider provider = new AbstractAcmeClientProvider() {
            @Override
            public boolean accepts(URI serverUri) {
                return serverUri.equals(testAcmeUri);
            }

            @Override
            protected URI resolve(URI serverUri) {
                assertThat(serverUri, is(testAcmeUri));
                return testDirectoryUri;
            }

            @Override
            protected AcmeClient createAcmeClient(URI directoryUri) {
                assertThat(directoryUri, is(equalTo(testDirectoryUri)));
                return super.createAcmeClient(directoryUri);
            }
        };

        AcmeClient client = provider.connect(testAcmeUri);
        assertThat(client, is(notNullValue()));

        try {
            provider.connect(new URI("acme://example.org/isbad"));
            fail("accepted unknown acme API");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test that challenges are generated properly.
     */
    @Test
    @SuppressWarnings("deprecation") // must test deprecated challenges
    public void testCreateChallenge() {
        AbstractAcmeClientProvider provider = new AbstractAcmeClientProvider() {
            @Override
            public boolean accepts(URI serverUri) {
                throw new UnsupportedOperationException();
            }

            @Override
            protected URI resolve(URI serverUri) {
                throw new UnsupportedOperationException();
            }
        };

        Challenge c1 = provider.createChallenge(Http01Challenge.TYPE);
        assertThat(c1, not(nullValue()));
        assertThat(c1, instanceOf(Http01Challenge.class));

        Challenge c2 = provider.createChallenge(Http01Challenge.TYPE);
        assertThat(c2, not(sameInstance(c1)));

        Challenge c3 = provider.createChallenge(Dns01Challenge.TYPE);
        assertThat(c3, not(nullValue()));
        assertThat(c3, instanceOf(Dns01Challenge.class));

        Challenge c4 = provider.createChallenge(ProofOfPossession01Challenge.TYPE);
        assertThat(c4, not(nullValue()));
        assertThat(c4, instanceOf(ProofOfPossession01Challenge.class));

        Challenge c5 = provider.createChallenge(org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE);
        assertThat(c5, not(nullValue()));
        assertThat(c5, instanceOf(org.shredzone.acme4j.challenge.TlsSni01Challenge.class));

        Challenge c6 = provider.createChallenge(TlsSni02Challenge.TYPE);
        assertThat(c6, not(nullValue()));
        assertThat(c6, instanceOf(TlsSni02Challenge.class));

        Challenge c7 = provider.createChallenge("foobar-01");
        assertThat(c7, is(nullValue()));

        try {
            provider.createChallenge(null);
            fail("null was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            provider.createChallenge("");
            fail("empty string was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

}
