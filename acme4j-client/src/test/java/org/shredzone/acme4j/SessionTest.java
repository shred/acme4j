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
import static org.mockito.Mockito.*;
import static org.shredzone.acme4j.util.TestUtils.getJsonAsObject;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit test for {@link Session}.
 */
public class SessionTest {

    /**
     * Test constructor
     */
    @Test
    public void testConstructor() throws IOException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        try {
            new Session((URI) null, null);
            fail("accepted null parameters in constructor");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            new Session(serverUri, null);
            fail("accepted null parameters in constructor");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            new Session((URI) null, keyPair);
            fail("accepted null parameters in constructor");
        } catch (NullPointerException ex) {
            // expected
        }

        Session session = new Session(serverUri, keyPair);
        assertThat(session, not(nullValue()));
        assertThat(session.getServerUri(), is(serverUri));
        assertThat(session.getKeyPair(), is(keyPair));

        Session session2 = new Session("https://example.com/acme", keyPair);
        assertThat(session2, not(nullValue()));
        assertThat(session2.getServerUri(), is(serverUri));
        assertThat(session2.getKeyPair(), is(keyPair));

        try {
            new Session("#*aBaDuRi*#", keyPair);
            fail("accepted bad URI in constructor");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test getters and setters.
     */
    @Test
    public void testGettersAndSetters() throws IOException {
        KeyPair kp1 = TestUtils.createKeyPair();
        KeyPair kp2 = TestUtils.createDomainKeyPair();
        URI serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        Session session = new Session(serverUri, kp1);

        assertThat(session.getNonce(), is(nullValue()));
        byte[] data = "foo-nonce-bar".getBytes();
        session.setNonce(data);
        assertThat(session.getNonce(), is(equalTo(data)));

        assertThat(session.getKeyPair(), is(kp1));
        session.setKeyPair(kp2);
        assertThat(session.getKeyPair(), is(kp2));

        assertThat(session.getServerUri(), is(serverUri));
    }

    /**
     * Test if challenges are correctly created via provider.
     */
    @Test
    public void testCreateChallenge() throws IOException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = URI.create(TestUtils.ACME_SERVER_URI);
        String challengeType = Http01Challenge.TYPE;

        JSON data = new JSONBuilder()
                        .put("type", challengeType)
                        .toJSON();

        Http01Challenge mockChallenge = mock(Http01Challenge.class);
        final AcmeProvider mockProvider = mock(AcmeProvider.class);

        when(mockProvider.createChallenge(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(challengeType)))
                .thenReturn(mockChallenge);

        Session session = new Session(serverUri, keyPair) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            };
        };

        Challenge challenge = session.createChallenge(data);
        assertThat(challenge, is(instanceOf(Http01Challenge.class)));
        assertThat(challenge, is(sameInstance((Challenge) mockChallenge)));

        verify(mockProvider).createChallenge(session, challengeType);
    }

    /**
     * Test that the directory is properly read and cached.
     */
    @Test
    public void testDirectory() throws AcmeException, IOException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        final AcmeProvider mockProvider = mock(AcmeProvider.class);
        when(mockProvider.directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(serverUri)))
                .thenReturn(getJsonAsObject("directory"));

        Session session = new Session(serverUri, keyPair) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            };
        };

        assertSession(session);

        // Make sure directory is only read once!
        verify(mockProvider, times(1)).directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.any(URI.class));

        // Simulate a cache expiry
        session.directoryCacheExpiry = Instant.now();

        // Make sure directory is read once again
        assertSession(session);
        verify(mockProvider, times(2)).directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.any(URI.class));
    }

    /**
     * Test that the directory is properly read even if there are no metadata.
     */
    @Test
    public void testNoMeta() throws AcmeException, IOException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        final AcmeProvider mockProvider = mock(AcmeProvider.class);
        when(mockProvider.directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(serverUri)))
                .thenReturn(getJsonAsObject("directoryNoMeta"));

        Session session = new Session(serverUri, keyPair) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            };
        };

        assertThat(session.resourceUri(Resource.NEW_REG),
                        is(URI.create("https://example.com/acme/new-reg")));
        assertThat(session.resourceUri(Resource.NEW_AUTHZ),
                        is(URI.create("https://example.com/acme/new-authz")));
        assertThat(session.resourceUri(Resource.NEW_CERT),
                        is(URI.create("https://example.com/acme/new-cert")));
        assertThat(session.resourceUri(Resource.REVOKE_CERT),
                        is(nullValue()));

        Metadata meta = session.getMetadata();
        assertThat(meta, not(nullValue()));
        assertThat(meta.getTermsOfService(), is(nullValue()));
        assertThat(meta.getWebsite(), is(nullValue()));
        assertThat(meta.getCaaIdentities(), is(empty()));
    }

    /**
     * Asserts that the {@link Session} returns correct
     * {@link Session#resourceUri(Resource)} and {@link Session#getMetadata()}.
     *
     * @param session
     *            {@link Session} to assert
     */
    private void assertSession(Session session) throws AcmeException {
        assertThat(session.resourceUri(Resource.NEW_REG),
                        is(URI.create("https://example.com/acme/new-reg")));
        assertThat(session.resourceUri(Resource.NEW_AUTHZ),
                        is(URI.create("https://example.com/acme/new-authz")));
        assertThat(session.resourceUri(Resource.NEW_CERT),
                        is(URI.create("https://example.com/acme/new-cert")));
        assertThat(session.resourceUri(Resource.REVOKE_CERT),
                        is(nullValue()));

        Metadata meta = session.getMetadata();
        assertThat(meta, not(nullValue()));
        assertThat(meta.getTermsOfService(), is(URI.create("https://example.com/acme/terms")));
        assertThat(meta.getWebsite(), is(URI.create("https://www.example.com/")));
        assertThat(meta.getCaaIdentities(), containsInAnyOrder("example.com"));
        assertThat(meta.getJSON(), is(notNullValue()));
    }

}
