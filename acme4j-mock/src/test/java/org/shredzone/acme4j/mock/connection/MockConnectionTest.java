/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static java.util.Collections.singletonList;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit test for {@link MockConnection}.
 */
public class MockConnectionTest {
    private static final KeyPair KEY = KeyPairUtils.createKeyPair(1024);

    /**
     * Test {@link MockConnection#sendRequest(URL, Session)}
     */
    @Test
    public void testSendRequest() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        Controller controller = mock(Controller.class);

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Session session = server.createSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        connection.sendRequest(requestUrl, session);

        verify(controller).doSimpleRequest(eq(requestUrl));
        verifyNoMoreInteractions(controller);
        assertThat(server.isValidNonce(session.getNonce()), is(true));
    }

    /**
     * Test {@link MockConnection#sendCertificateRequest(URL, Login)}
     */
    @Test
    public void testSendCertificateRequest() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        Controller controller = mock(Controller.class);

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Login login = server.createLogin(KEY);
        Session session = login.getSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        int rc = connection.sendCertificateRequest(requestUrl, login);

        assertThat(rc, is(HttpURLConnection.HTTP_OK));
        verify(controller).doPostAsGetRequest(eq(requestUrl), eq(KEY.getPublic()));
        verifyNoMoreInteractions(controller);
        assertThat(server.isValidNonce(session.getNonce()), is(true));
    }

    /**
     * Test {@link MockConnection#sendSignedPostAsGetRequest(URL, Login)}
     */
    @Test
    public void testSendSignedPostAsGetRequest() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        Controller controller = mock(Controller.class);

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Login login = server.createLogin(KEY);
        Session session = login.getSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        int rc = connection.sendSignedPostAsGetRequest(requestUrl, login);

        assertThat(rc, is(HttpURLConnection.HTTP_OK));
        verify(controller).doPostAsGetRequest(eq(requestUrl), eq(KEY.getPublic()));
        verifyNoMoreInteractions(controller);
        assertThat(server.isValidNonce(session.getNonce()), is(true));
    }

    /**
     * Test {@link MockConnection#sendSignedRequest(URL, JSONBuilder, Login)}
     */
    @Test
    public void testSendSignedRequestWithLogin() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        Controller controller = mock(Controller.class);

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Login login = server.createLogin(KEY);
        Session session = login.getSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        JSONBuilder claims = new JSONBuilder();
        int rc = connection.sendSignedRequest(requestUrl, claims, login);

        assertThat(rc, is(HttpURLConnection.HTTP_OK));
        verify(controller).doPostRequest(eq(requestUrl), any(), eq(KEY.getPublic()));
        verifyNoMoreInteractions(controller);
        assertThat(server.isValidNonce(session.getNonce()), is(true));
    }

    /**
     * Test {@link MockConnection#sendSignedRequest(URL, JSONBuilder, Session, KeyPair)}
     */
    @Test
    public void testSendSignedRequest() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        Controller controller = mock(Controller.class);

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Session session = server.createSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        JSONBuilder claims = new JSONBuilder();
        int rc = connection.sendSignedRequest(requestUrl, claims, session, KEY);

        assertThat(rc, is(HttpURLConnection.HTTP_OK));
        verify(controller).doPostRequest(eq(requestUrl), any(), eq(KEY.getPublic()));
        verifyNoMoreInteractions(controller);
        assertThat(server.isValidNonce(session.getNonce()), is(true));
    }

    /**
     * Test {@link MockConnection#readJsonResponse()}
     */
    @Test
    public void testJsonResponse() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        URL locationUrl = new URL("https://mock.test/location");
        JSONBuilder sentJson = new JSONBuilder();
        sentJson.put("abc", 123);
        Instant retryAfter = Instant.now().plus(30, ChronoUnit.MINUTES);

        Controller controller = mock(Controller.class);
        when(controller.doPostRequest(eq(requestUrl), any(), eq(KEY.getPublic())))
                .thenReturn(new Result(sentJson.toJSON(), locationUrl, retryAfter));

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Session session = server.createSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        connection.sendSignedRequest(requestUrl, new JSONBuilder(), session, KEY);

        JSON response = connection.readJsonResponse();
        assertThat(response.toString(), sameJSONAs(sentJson.toString()));
        assertThat(connection.getLocation(), is(locationUrl));
        assertThat(connection.getLinks("next"), is(empty()));

        try {
            connection.handleRetryAfter("try again later");
            fail("No Retry-After");
        } catch (AcmeRetryAfterException ex) {
            // expected
        }
    }

    /**
     * Test {@link MockConnection#readCertificates()}
     */
    @Test
    public void testCertificateResponse() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://mock.test/foo");
        List<X509Certificate> sentCerts = singletonList(mock(X509Certificate.class));

        Controller controller = mock(Controller.class);
        when(controller.doPostRequest(eq(requestUrl), any(), eq(KEY.getPublic())))
                .thenReturn(new Result(sentCerts));

        MockAcmeServer server = new MockAcmeServer();
        server.getRepository().addController(requestUrl, controller);

        Session session = server.createSession();
        Connection connection = session.connect();
        assertThat(connection, instanceOf(MockConnection.class));

        connection.sendSignedRequest(requestUrl, new JSONBuilder(), session, KEY);

        List<X509Certificate> certs = connection.readCertificates();
        assertThat(certs, is(sentCerts));
        assertThat(connection.getLinks("next"), is(empty()));

        connection.handleRetryAfter("try again later");
    }

}
