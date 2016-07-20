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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit test for {@link Session}.
 *
 * @author Richard "Shred" Körber
 */
public class SessionTest {

    /**
     * Test constructor
     */
    @Test
    public void testConstructor() throws Exception {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = new URI(TestUtils.ACME_SERVER_URI);

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
    public void testGettersAndSetters() throws Exception {
        KeyPair kp1 = TestUtils.createKeyPair();
        KeyPair kp2 = TestUtils.createDomainKeyPair();
        URI serverUri = new URI(TestUtils.ACME_SERVER_URI);

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
    public void testCreateChallenge() throws IOException, URISyntaxException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = new URI(TestUtils.ACME_SERVER_URI);
        String challengeType = Http01Challenge.TYPE;

        Map<String, Object> data = new ClaimBuilder()
                        .put("type", challengeType)
                        .toMap();

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
    public void testResourceUri() throws AcmeException, IOException, URISyntaxException {
        KeyPair keyPair = TestUtils.createKeyPair();
        URI serverUri = new URI(TestUtils.ACME_SERVER_URI);

        Map<Resource, URI> directoryMap = new HashMap<>();
        directoryMap.put(Resource.NEW_AUTHZ, new URI("http://example.com/acme/new-authz"));
        directoryMap.put(Resource.NEW_CERT, new URI("http://example.com/acme/new-cert"));

        final AcmeProvider mockProvider = mock(AcmeProvider.class);
        when(mockProvider.resources(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(serverUri)))
                .thenReturn(directoryMap);

        Session session = new Session(serverUri, keyPair) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            };
        };

        assertThat(session.resourceUri(Resource.NEW_AUTHZ),
                        is(new URI("http://example.com/acme/new-authz")));
        assertThat(session.resourceUri(Resource.NEW_CERT),
                        is(new URI("http://example.com/acme/new-cert")));
        assertThat(session.resourceUri(Resource.NEW_REG),
                        is(nullValue()));

        // Make sure directory is only read once!
        verify(mockProvider, times(1)).resources(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.any(URI.class));

        // Simulate a cache expiry
        session.directoryCacheExpiry = new Date();

        // Make sure directory is read once again
        assertThat(session.resourceUri(Resource.NEW_AUTHZ),
                        is(new URI("http://example.com/acme/new-authz")));
        assertThat(session.resourceUri(Resource.NEW_CERT),
                        is(new URI("http://example.com/acme/new-cert")));
        assertThat(session.resourceUri(Resource.NEW_REG),
                        is(nullValue()));
        verify(mockProvider, times(2)).resources(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.any(URI.class));
    }

}
