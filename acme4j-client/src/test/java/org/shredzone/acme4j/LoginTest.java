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
        var location = url(TestUtils.ACCOUNT_URL);
        var keypair = TestUtils.createKeyPair();
        var session = TestUtils.session();

        var login = new Login(location, keypair, session);
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
        var location = url(TestUtils.ACCOUNT_URL);
        var keypair = TestUtils.createKeyPair();
        var session = TestUtils.session();

        var login = new Login(location, keypair, session);

        var auth = login.bindAuthorization(resourceUrl);
        assertThat(auth).isNotNull();
        assertThat(auth.getLogin()).isEqualTo(login);
        assertThat(auth.getLocation()).isEqualTo(resourceUrl);

        var cert = login.bindCertificate(resourceUrl);
        assertThat(cert).isNotNull();
        assertThat(cert.getLogin()).isEqualTo(login);
        assertThat(cert.getLocation()).isEqualTo(resourceUrl);

        var order = login.bindOrder(resourceUrl);
        assertThat(order).isNotNull();
        assertThat(order.getLogin()).isEqualTo(login);
        assertThat(order.getLocation()).isEqualTo(resourceUrl);
    }

    /**
     * Test that the account's keypair can be changed.
     */
    @Test
    public void testKeyChange() throws IOException {
        var location = url(TestUtils.ACCOUNT_URL);
        var keypair = TestUtils.createKeyPair();
        var session = TestUtils.session();

        var login = new Login(location, keypair, session);
        assertThat(login.getKeyPair()).isEqualTo(keypair);

        var keypair2 = TestUtils.createKeyPair();
        login.setKeyPair(keypair2);
        assertThat(login.getKeyPair()).isEqualTo(keypair2);
    }

    /**
     * Test that challenges are correctly created via provider.
     */
    @Test
    public void testCreateChallenge() throws Exception {
        var challengeType = Http01Challenge.TYPE;
        var challengeUrl = url("https://example.com/acme/authz/0");

        var data = new JSONBuilder()
                        .put("type", challengeType)
                        .put("url", challengeUrl)
                        .toJSON();

        var mockChallenge = mock(Http01Challenge.class);
        var mockProvider = mock(AcmeProvider.class);

        when(mockProvider.createChallenge(
                        ArgumentMatchers.any(Login.class),
                        ArgumentMatchers.eq(data)))
                .thenReturn(mockChallenge);

        var location = url(TestUtils.ACCOUNT_URL);
        var keypair = TestUtils.createKeyPair();
        var session = TestUtils.session(mockProvider);

        var login = new Login(location, keypair, session);
        var challenge = login.createChallenge(data);
        assertThat(challenge).isInstanceOf(Http01Challenge.class);
        assertThat(challenge).isSameAs(mockChallenge);

        verify(mockProvider).createChallenge(login, data);
    }

    /**
     * Test that binding to a challenge invokes createChallenge
     */
    @Test
    public void testBindChallenge() throws Exception {
        var locationUrl = new URL("https://example.com/acme/challenge/1");

        var mockChallenge = mock(Http01Challenge.class);
        when(mockChallenge.getType()).thenReturn(Http01Challenge.TYPE);
        var httpChallenge = getJSON("httpChallenge");
        var provider  = new TestableConnectionProvider() {
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

        var login = provider.createLogin();
        var challenge = login.bindChallenge(locationUrl);
        assertThat(challenge).isInstanceOf(Http01Challenge.class);
        assertThat(challenge).isSameAs(mockChallenge);

        var challenge2 = login.bindChallenge(locationUrl, Http01Challenge.class);
        assertThat(challenge2).isSameAs(mockChallenge);

        var ex = assertThrows(AcmeProtocolException.class,
                () -> login.bindChallenge(locationUrl, Dns01Challenge.class));
        assertThat(ex.getMessage()).isEqualTo("Challenge type http-01 does not match" +
                " requested class class org.shredzone.acme4j.challenge.Dns01Challenge");
    }

}
