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
package org.shredzone.acme4j.connector;

import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jose4j.base64url.Base64Url;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link PreDraft15Connection}.
 */
@SuppressWarnings("deprecation")
public class PreDraft15ConnectionTest {

    private URL requestUrl = TestUtils.url("http://example.com/acme/");
    private URL accountUrl = TestUtils.url(TestUtils.ACCOUNT_URL);
    private HttpURLConnection mockUrlConnection;
    private HttpConnector mockHttpConnection;
    private Session session;
    private Login login;
    private KeyPair keyPair;

    @Before
    public void setup() throws AcmeException, IOException {
        mockUrlConnection = mock(HttpURLConnection.class);

        mockHttpConnection = mock(HttpConnector.class);
        when(mockHttpConnection.openConnection(requestUrl, Proxy.NO_PROXY)).thenReturn(mockUrlConnection);

        final AcmeProvider mockProvider = mock(AcmeProvider.class);
        when(mockProvider.directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(URI.create(TestUtils.ACME_SERVER_URI))))
            .thenReturn(TestUtils.getJSON("directory"));

        session = TestUtils.session(mockProvider);
        session.setLocale(Locale.JAPAN);

        keyPair = TestUtils.createKeyPair();

        login = session.login(accountUrl, keyPair);
    }

    /**
     * Test signed POST-as-GET requests in compatibility mode.
     */
    @Test
    public void testSendSignedPostAsGetRequest() throws Exception {
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);

        try (PreDraft15Connection conn = new PreDraft15Connection(mockHttpConnection) {
            @Override
            public String getNonce() {
                return Base64Url.encode("foo-nonce-1-foo".getBytes());
            }
        }) {
            conn.sendSignedPostAsGetRequest(requestUrl, login);
        }

        verify(mockUrlConnection).setRequestMethod("GET");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/json");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setDoOutput(false);
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test update requests to Account in compatibility mode.
     */
    @Test
    public void testUpdateAccountRequest() throws Exception {
        final AtomicBoolean wasInvoked = new AtomicBoolean();

        try (PreDraft15Connection conn = new PreDraft15Connection(mockHttpConnection) {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
                assertThat(url, is(accountUrl));
                assertThat(claims.toString(), is("{}"));
                assertThat(login, is(sameInstance(PreDraft15ConnectionTest.this.login)));
                wasInvoked.set(true);
                return HttpURLConnection.HTTP_OK;
            };
        }) {
            conn.sendSignedPostAsGetRequest(accountUrl, login);
        }

        assertThat(wasInvoked.get(), is(true));
    }

    /**
     * Test certificate POST-as-GET requests in compatibility mode.
     */
    @Test
    public void testSendCertificateRequest() throws Exception {
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);

        try (PreDraft15Connection conn = new PreDraft15Connection(mockHttpConnection) {
            @Override
            public String getNonce() {
                return Base64Url.encode("foo-nonce-1-foo".getBytes());
            }
        }) {
            conn.sendCertificateRequest(requestUrl, login);
        }

        verify(mockUrlConnection).setRequestMethod("GET");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/pem-certificate-chain");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setDoOutput(false);
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);
    }

}
