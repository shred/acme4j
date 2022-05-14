/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Login}.
 */
public class LoginTest {

    private final URL resourceUrl = url("https://example.com/acme/resource/123");

    /**
     * Test the constructor.
     */
    @Test
    public void testConstructor() throws IOException {
        URL location = url(TestUtils.ACCOUNT_URL);
        KeyPair keypair = TestUtils.createKeyPair();
        Session session = TestUtils.session();

        Login login = new Login(location, keypair, session);
        assertThat(login.getAccountLocation()).isEqualTo(location);
        assertThat(login.getKeyPair()).isEqualTo(keypair);
        assertThat(login.getSession()).isEqualTo(session);

        assertThat(login.getAccount()).isNotNull();
        assertThat(login.getAccount().getLogin()).isEqualTo(login);
        assertThat(login.getAccount().getLocation()).isEqualTo(location);
        assertThat(login.getAccount().getSession()).isEqualTo(session);
    }

    /**
     * Test the simple binders.
     */
    @Test
    public void testBinder() throws IOException {
        URL location = url(TestUtils.ACCOUNT_URL);
        KeyPair keypair = TestUtils.createKeyPair();
        Session session = TestUtils.session();

        Login login = new Login(location, keypair, session);

        Authorization auth = login.bindAuthorization(resourceUrl);
        assertThat(auth).isNotNull();
        assertThat(auth.getLogin()).isEqualTo(login);
        assertThat(auth.getLocation()).isEqualTo(resourceUrl);

        Certificate cert = login.bindCertificate(resourceUrl);
        assertThat(cert).isNotNull();
        assertThat(cert.getLogin()).isEqualTo(login);
        assertThat(cert.getLocation()).isEqualTo(resourceUrl);

        Order order = login.bindOrder(resourceUrl);
        assertThat(order).isNotNull();
        assertThat(order.getLogin()).isEqualTo(login);
        assertThat(order.getLocation()).isEqualTo(resourceUrl);
    }

    /**
     * Test that the account's keypair can be changed.
     */
    @Test
    public void testKeyChange() throws IOException {
        URL location = url(TestUtils.ACCOUNT_URL);
        KeyPair keypair = TestUtils.createKeyPair();
        Session session = TestUtils.session();

        Login login = new Login(location, keypair, session);
        assertThat(login.getKeyPair()).isEqualTo(keypair);

        KeyPair keypair2 = TestUtils.createKeyPair();
        login.setKeyPair(keypair2);
        assertThat(login.getKeyPair()).isEqualTo(keypair2);
    }

    /**
     * Test that challenges are correctly created via provider.
     */
    @Test
    public void testCreateChallenge() throws Exception {
        String challengeType = Http01Challenge.TYPE;
        URL challengeUrl = url("https://example.com/acme/authz/0");

        JSON data = new JSONBuilder()
                        .put("type", challengeType)
                        .put("url", challengeUrl)
                        .toJSON();

        Http01Challenge mockChallenge = mock(Http01Challenge.class);
        final AcmeProvider mockProvider = mock(AcmeProvider.class);

        when(mockProvider.createChallenge(
                        ArgumentMatchers.any(Login.class),
                        ArgumentMatchers.eq(data)))
                .thenReturn(mockChallenge);

        URL location = url(TestUtils.ACCOUNT_URL);
        KeyPair keypair = TestUtils.createKeyPair();
        Session session = TestUtils.session(mockProvider);

        Login login = new Login(location, keypair, session);
        Challenge challenge = login.createChallenge(data);
        assertThat(challenge).isInstanceOf(Http01Challenge.class);
        assertThat(challenge).isSameAs(mockChallenge);

        verify(mockProvider).createChallenge(login, data);
    }

    /**
     * Test that binding to a challenge invokes createChallenge
     */
    @Test
    public void testBindChallenge() throws Exception {
        URL locationUrl = new URL("https://example.com/acme/challenge/1");

        Http01Challenge mockChallenge = mock(Http01Challenge.class);
        when(mockChallenge.getType()).thenReturn(Http01Challenge.TYPE);
        JSON httpChallenge = getJSON("httpChallenge");
        TestableConnectionProvider provider  = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return httpChallenge;
            }

            @Override
            public Challenge createChallenge(Login login, JSON json) {
                assertThat(json).isEqualTo(httpChallenge);
                return mockChallenge;
            }
        };

        Login login = provider.createLogin();
        Challenge challenge = login.bindChallenge(locationUrl);
        assertThat(challenge).isInstanceOf(Http01Challenge.class);
        assertThat(challenge).isSameAs(mockChallenge);

        Http01Challenge challenge2 = login.bindChallenge(locationUrl, Http01Challenge.class);
        assertThat(challenge2).isSameAs(mockChallenge);

        AcmeProtocolException ex = assertThrows(AcmeProtocolException.class,
                () -> login.bindChallenge(locationUrl, Dns01Challenge.class));
        assertThat(ex.getMessage()).isEqualTo("Challenge type http-01 does not match" +
                " requested class class org.shredzone.acme4j.challenge.Dns01Challenge");
    }

}
