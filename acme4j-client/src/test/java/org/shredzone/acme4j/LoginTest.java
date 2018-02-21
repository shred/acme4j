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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Login}.
 */
public class LoginTest {

    private static final URL resourceUrl = url("https://example.com/acme/resource/123");

    /**
     * Test the constructor.
     */
    @Test
    public void testConstructor() throws IOException {
        URL location = url(TestUtils.ACCOUNT_URL);
        KeyPair keypair = TestUtils.createKeyPair();
        Session session = TestUtils.session();

        Login login = new Login(location, keypair, session);
        assertThat(login.getAccountLocation(), is(location));
        assertThat(login.getKeyPair(), is(keypair));
        assertThat(login.getSession(), is(session));

        assertThat(login.getAccount(), is(notNullValue()));
        assertThat(login.getAccount().getLogin(), is(login));
        assertThat(login.getAccount().getLocation(), is(location));
        assertThat(login.getAccount().getSession(), is(session));
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
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getLogin(), is(login));
        assertThat(auth.getLocation(), is(resourceUrl));

        Certificate cert = login.bindCertificate(resourceUrl);
        assertThat(cert, is(notNullValue()));
        assertThat(cert.getLogin(), is(login));
        assertThat(cert.getLocation(), is(resourceUrl));

        Order order = login.bindOrder(resourceUrl);
        assertThat(order, is(notNullValue()));
        assertThat(order.getLogin(), is(login));
        assertThat(order.getLocation(), is(resourceUrl));
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
        assertThat(login.getKeyPair(), is(keypair));

        KeyPair keypair2 = TestUtils.createKeyPair();
        login.setKeyPair(keypair2);
        assertThat(login.getKeyPair(), is(keypair2));
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
        assertThat(challenge, is(instanceOf(Http01Challenge.class)));
        assertThat(challenge, is(sameInstance((Challenge) mockChallenge)));

        verify(mockProvider).createChallenge(login, data);
    }

}
