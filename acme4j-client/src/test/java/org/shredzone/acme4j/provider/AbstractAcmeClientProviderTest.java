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
import org.shredzone.acme4j.challenge.DnsChallenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.challenge.ProofOfPossessionChallenge;
import org.shredzone.acme4j.challenge.TlsSniChallenge;

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
     * Test that all base challenges are registered on initialization, and that additional
     * challenges are properly registered.
     */
    @Test
    public void testRegisterChallenges() {
        AbstractAcmeClientProvider provider = new AbstractAcmeClientProvider() {
            @Override
            protected void registerBaseChallenges() {
                assertThat(getRegisteredChallengeTypes(), is(empty()));
                super.registerBaseChallenges();
            }

            @Override
            public boolean accepts(URI serverUri) {
                throw new UnsupportedOperationException();
            }

            @Override
            protected URI resolve(URI serverUri) {
                throw new UnsupportedOperationException();
            }
        };

        assertThat(provider.getRegisteredChallengeTypes(), hasSize(4));
        assertThat(provider.getRegisteredChallengeTypes(), containsInAnyOrder(
                DnsChallenge.TYPE,
                HttpChallenge.TYPE,
                ProofOfPossessionChallenge.TYPE,
                TlsSniChallenge.TYPE
        ));

        provider.registerChallenge("foo", GenericChallenge.class);

        assertThat(provider.getRegisteredChallengeTypes(), hasSize(5));
        assertThat(provider.getRegisteredChallengeTypes(), containsInAnyOrder(
                DnsChallenge.TYPE,
                HttpChallenge.TYPE,
                ProofOfPossessionChallenge.TYPE,
                TlsSniChallenge.TYPE,
                "foo"
        ));

        try {
            provider.registerChallenge(null, GenericChallenge.class);
            fail("accepts null type");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            provider.registerChallenge("bar", null);
            fail("accepts null class");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            provider.registerChallenge("", GenericChallenge.class);
            fail("accepts empty type");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test that challenges are generated properly.
     */
    @Test
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

        Challenge c1 = provider.createChallenge(HttpChallenge.TYPE);
        assertThat(c1, not(nullValue()));
        assertThat(c1, instanceOf(HttpChallenge.class));

        Challenge c2 = provider.createChallenge(HttpChallenge.TYPE);
        assertThat(c2, not(sameInstance(c1)));

        Challenge c3 = provider.createChallenge(DnsChallenge.TYPE);
        assertThat(c3, not(nullValue()));
        assertThat(c3, instanceOf(DnsChallenge.class));

        Challenge c4 = provider.createChallenge(ProofOfPossessionChallenge.TYPE);
        assertThat(c4, not(nullValue()));
        assertThat(c4, instanceOf(ProofOfPossessionChallenge.class));

        Challenge c5 = provider.createChallenge(TlsSniChallenge.TYPE);
        assertThat(c5, not(nullValue()));
        assertThat(c5, instanceOf(TlsSniChallenge.class));

        Challenge c6 = provider.createChallenge("foobar-01");
        assertThat(c6, not(nullValue()));
        assertThat(c6, instanceOf(GenericChallenge.class));
    }

}
