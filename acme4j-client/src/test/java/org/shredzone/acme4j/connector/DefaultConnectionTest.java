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
package org.shredzone.acme4j.connector;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link DefaultConnection}.
 */
public class DefaultConnectionTest {

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
     * Test that {@link DefaultConnection#getNonce()} returns {@code null} if there is no
     * {@code Replay-Nonce} header.
     */
    @Test
    public void testNoNonceFromHeader() {
        when(mockUrlConnection.getHeaderField("Replay-Nonce")).thenReturn(null);

        assertThat(session.getNonce(), is(nullValue()));
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getNonce(), is(nullValue()));
        }

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} extracts a {@code Replay-Nonce}
     * header correctly.
     */
    @Test
    public void testGetNonceFromHeader() {
        when(mockUrlConnection.getHeaderField("Replay-Nonce"))
                .thenReturn(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getNonce(), is(TestUtils.DUMMY_NONCE));
        }

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} fails on an invalid
     * {@code Replay-Nonce} header.
     */
    @Test
    public void testInvalidNonceFromHeader() {
        String badNonce = "#$%&/*+*#'";

        when(mockUrlConnection.getHeaderField("Replay-Nonce")).thenReturn(badNonce);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.getNonce();
            fail("Expected to fail");
        } catch (AcmeProtocolException ex) {
            assertThat(ex.getMessage(), org.hamcrest.Matchers.startsWith("Invalid replay nonce"));
        }

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that {@link DefaultConnection#resetNonce(Session)} fetches a new nonce via
     * new-nonce resource and a HEAD request.
     */
    @Test
    public void testResetNonce() throws AcmeException, IOException {
        when(mockHttpConnection.openConnection(new URL("https://example.com/acme/new-nonce"), Proxy.NO_PROXY))
                .thenReturn(mockUrlConnection);
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_NO_CONTENT);

        assertThat(session.getNonce(), is(nullValue()));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.resetNonce(session);
            fail("missing Replay-Nonce header not detected");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        assertThat(session.getNonce(), is(nullValue()));

        when(mockUrlConnection.getHeaderField("Replay-Nonce"))
                .thenReturn(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.resetNonce(session);
        }

        assertThat(session.getNonce(), is(TestUtils.DUMMY_NONCE));

        verify(mockUrlConnection, atLeastOnce()).setRequestMethod("HEAD");
        verify(mockUrlConnection, atLeastOnce()).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection, atLeastOnce()).connect();
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Replay-Nonce");
        verify(mockUrlConnection, atLeastOnce()).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that an absolute Location header is evaluated.
     */
    @Test
    public void testGetAbsoluteLocation() throws Exception {
        when(mockUrlConnection.getHeaderField("Location")).thenReturn("https://example.com/otherlocation");
        when(mockUrlConnection.getURL()).thenReturn(new URL("https://example.org/acme"));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            URL location = conn.getLocation();
            assertThat(location, is(new URL("https://example.com/otherlocation")));
        }

        verify(mockUrlConnection).getHeaderField("Location");
        verify(mockUrlConnection).getURL();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that a relative Location header is evaluated.
     */
    @Test
    public void testGetRelativeLocation() throws Exception {
        when(mockUrlConnection.getHeaderField("Location")).thenReturn("/otherlocation");
        when(mockUrlConnection.getURL()).thenReturn(new URL("https://example.org/acme"));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            URL location = conn.getLocation();
            assertThat(location, is(new URL("https://example.org/otherlocation")));
        }

        verify(mockUrlConnection).getHeaderField("Location");
        verify(mockUrlConnection).getURL();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that absolute and relative Link headers are evaluated.
     */
    @Test
    public void testGetLink() throws Exception {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Content-Type", Arrays.asList("application/json"));
        headers.put("Location", Arrays.asList("https://example.com/acme/acct/asdf"));
        headers.put("Link", Arrays.asList(
                        "<https://example.com/acme/new-authz>;rel=\"next\"",
                        "</recover-acct>;rel=recover",
                        "<https://example.com/acme/terms>; rel=\"terms-of-service\""
                    ));

        when(mockUrlConnection.getHeaderFields()).thenReturn(headers);
        when(mockUrlConnection.getURL()).thenReturn(new URL("https://example.org/acme"));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getLinks("next"), containsInAnyOrder(new URL("https://example.com/acme/new-authz")));
            assertThat(conn.getLinks("recover"), containsInAnyOrder(new URL("https://example.org/recover-acct")));
            assertThat(conn.getLinks("terms-of-service"), containsInAnyOrder(new URL("https://example.com/acme/terms")));
            assertThat(conn.getLinks("secret-stuff"), is(empty()));
        }
    }

    /**
     * Test that multiple link headers are evaluated.
     */
    @Test
    public void testGetMultiLink() {
        URL baseUrl = url("https://example.com/acme/request/1234");

        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Link", Arrays.asList(
                        "<https://example.com/acme/terms1>; rel=\"terms-of-service\"",
                        "<https://example.com/acme/terms2>; rel=\"terms-of-service\"",
                        "<../terms3>; rel=\"terms-of-service\""
                    ));

        when(mockUrlConnection.getHeaderFields()).thenReturn(headers);
        when(mockUrlConnection.getURL()).thenReturn(baseUrl);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getLinks("terms-of-service"), containsInAnyOrder(
                        url("https://example.com/acme/terms1"),
                        url("https://example.com/acme/terms2"),
                        url("https://example.com/acme/terms3")
            ));
        }
    }

    /**
     * Test that no link headers are properly handled.
     */
    @Test
    public void testGetNoLink() {
        Map<String, List<String>> headers = Collections.emptyMap();
        when(mockUrlConnection.getHeaderFields()).thenReturn(headers);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getLinks("something"), is(empty()));
        }
    }

    /**
     * Test that no Location header returns {@code null}.
     */
    @Test
    public void testNoLocation() {
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            URL location = conn.getLocation();
            assertThat(location, is(nullValue()));
        }

        verify(mockUrlConnection).getHeaderField("Location");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if Retry-After header with absolute date is correctly parsed.
     */
    @Test
    public void testHandleRetryAfterHeaderDate() throws AcmeException, IOException {
        Instant retryDate = Instant.now().plus(Duration.ofHours(10)).truncatedTo(ChronoUnit.MILLIS);
        String retryMsg = "absolute date";

        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getHeaderField("Retry-After")).thenReturn(retryDate.toString());
        when(mockUrlConnection.getHeaderFieldDate("Retry-After", 0L)).thenReturn(retryDate.toEpochMilli());

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.handleRetryAfter(retryMsg);
            fail("no AcmeRetryAfterException was thrown");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(retryDate));
            assertThat(ex.getMessage(), is(retryMsg));
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
    }

    /**
     * Test if Retry-After header with relative timespan is correctly parsed.
     */
    @Test
    public void testHandleRetryAfterHeaderDelta() throws AcmeException, IOException {
        int delta = 10 * 60 * 60;
        long now = System.currentTimeMillis();
        String retryMsg = "relative time";

        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getHeaderField("Retry-After"))
                .thenReturn(String.valueOf(delta));
        when(mockUrlConnection.getHeaderFieldDate(
                        ArgumentMatchers.eq("Date"),
                        ArgumentMatchers.anyLong()))
                .thenReturn(now);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.handleRetryAfter(retryMsg);
            fail("no AcmeRetryAfterException was thrown");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(Instant.ofEpochMilli(now).plusSeconds(delta)));
            assertThat(ex.getMessage(), is(retryMsg));
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
    }

    /**
     * Test if no Retry-After header is correctly handled.
     */
    @Test
    public void testHandleRetryAfterHeaderNull() throws AcmeException, IOException {
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getHeaderField("Retry-After"))
                .thenReturn(null);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.handleRetryAfter("no header");
        } catch (AcmeRetryAfterException ex) {
            fail("an AcmeRetryAfterException was thrown");
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
    }

    /**
     * Test if missing retry-after header is correctly handled.
     */
    @Test
    public void testHandleRetryAfterNotAccepted() throws AcmeException, IOException {
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.handleRetryAfter("http ok");
        } catch (AcmeRetryAfterException ex) {
            fail("an AcmeRetryAfterException was thrown");
        }
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on an acme problem.
     */
    @Test
    public void testAccept() throws Exception {
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            int rc = conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            assertThat(rc, is(HttpURLConnection.HTTP_OK));
        }

        verify(mockUrlConnection).getResponseCode();
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsException() throws Exception {
        String jsonData = "{\"type\":\"urn:ietf:params:acme:error:unauthorized\",\"detail\":\"Invalid response: 404\"}";

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/problem+json");
        when(mockUrlConnection.getContentLength()).thenReturn(jsonData.length());
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_FORBIDDEN);
        when(mockUrlConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockUrlConnection.getErrorStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));
        when(mockUrlConnection.getURL()).thenReturn(url("https://example.com/acme/1"));

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeUnauthorizedException ex) {
            assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:unauthorized")));
            assertThat(ex.getMessage(), is("Invalid response: 404"));
        } catch (AcmeException ex) {
            fail("Expected an AcmeUnauthorizedException");
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getContentLength();
        verify(mockUrlConnection).getErrorStream();
        verify(mockUrlConnection).getURL();
    }

    /**
     * Test if an {@link AcmeUserActionRequiredException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsUserActionRequiredException() throws Exception {
        String jsonData = "{\"type\":\"urn:ietf:params:acme:error:userActionRequired\",\"detail\":\"Accept the TOS\"}";

        Map<String, List<String>> linkHeader = new HashMap<>();
        linkHeader.put("Link", Arrays.asList("<https://example.com/tos.pdf>; rel=\"terms-of-service\""));

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/problem+json");
        when(mockUrlConnection.getContentLength()).thenReturn(jsonData.length());
        when(mockUrlConnection.getHeaderFields()).thenReturn(linkHeader);
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_FORBIDDEN);
        when(mockUrlConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockUrlConnection.getErrorStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));
        when(mockUrlConnection.getURL()).thenReturn(url("https://example.com/acme/1"));

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeUserActionRequiredException ex) {
            assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:userActionRequired")));
            assertThat(ex.getMessage(), is("Accept the TOS"));
            assertThat(ex.getTermsOfServiceUri(), is(URI.create("https://example.com/tos.pdf")));
        } catch (AcmeException ex) {
            fail("Expected an AcmeUserActionRequiredException");
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getHeaderFields();
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getErrorStream();
        verify(mockUrlConnection).getContentLength();
        verify(mockUrlConnection, atLeastOnce()).getURL();
    }

    /**
     * Test if an {@link AcmeRateLimitedException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsRateLimitedException() throws Exception {
        String jsonData = "{\"type\":\"urn:ietf:params:acme:error:rateLimited\",\"detail\":\"Too many invocations\"}";

        Map<String, List<String>> linkHeader = new HashMap<>();
        linkHeader.put("Link", Arrays.asList("<https://example.com/rates.pdf>; rel=\"urn:ietf:params:acme:documentation\""));

        Instant retryAfter = Instant.now().plusSeconds(30L).truncatedTo(ChronoUnit.MILLIS);

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/problem+json");
        when(mockUrlConnection.getContentLength()).thenReturn(jsonData.length());
        when(mockUrlConnection.getHeaderField("Retry-After")).thenReturn(retryAfter.toString());
        when(mockUrlConnection.getHeaderFieldDate("Retry-After", 0L)).thenReturn(retryAfter.toEpochMilli());
        when(mockUrlConnection.getHeaderFields()).thenReturn(linkHeader);
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_FORBIDDEN);
        when(mockUrlConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockUrlConnection.getErrorStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));
        when(mockUrlConnection.getURL()).thenReturn(url("https://example.com/acme/1"));

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeRateLimitedException ex) {
            assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:rateLimited")));
            assertThat(ex.getMessage(), is("Too many invocations"));
            assertThat(ex.getRetryAfter(), is(retryAfter));
            assertThat(ex.getDocuments(), is(notNullValue()));
            assertThat(ex.getDocuments().size(), is(1));
            assertThat(ex.getDocuments().iterator().next(), is(url("https://example.com/rates.pdf")));
        } catch (AcmeException ex) {
            fail("Expected an AcmeRateLimitedException");
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
        verify(mockUrlConnection).getHeaderFieldDate("Retry-After", 0L);
        verify(mockUrlConnection, atLeastOnce()).getHeaderFields();
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getContentLength();
        verify(mockUrlConnection).getErrorStream();
        verify(mockUrlConnection, atLeastOnce()).getURL();
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on another problem.
     */
    @Test
    public void testAcceptThrowsOtherException() throws IOException {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);
        when(mockUrlConnection.getURL())
                .thenReturn(url("https://example.com/acme/1"));
        when(mockUrlConnection.getOutputStream())
                .thenReturn(new ByteArrayOutputStream());

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public JSON readJsonResponse() {
                JSONBuilder result = new JSONBuilder();
                result.put("type", "urn:zombie:error:apocalypse");
                result.put("detail", "Zombie apocalypse in progress");
                return result.toJSON();
            }
        }) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is(URI.create("urn:zombie:error:apocalypse")));
            assertThat(ex.getMessage(), is("Zombie apocalypse in progress"));
        } catch (AcmeException ex) {
            fail("Expected an AcmeServerException");
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getURL();
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is no error type.
     */
    @Test
    public void testAcceptThrowsNoTypeException() throws IOException {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);
        when(mockUrlConnection.getURL())
                .thenReturn(url("https://example.com/acme/1"));
        when(mockUrlConnection.getOutputStream())
                .thenReturn(new ByteArrayOutputStream());

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public JSON readJsonResponse() {
                return JSON.empty();
            }
        }) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeProtocolException ex) {
            assertThat(ex.getMessage(), not(isEmptyOrNullString()));
        } catch (AcmeException ex) {
            fail("Did not expect an AcmeException");
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getURL();
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is a generic error.
     */
    @Test
    public void testAcceptThrowsServerException() throws IOException {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("text/html");
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);
        when(mockUrlConnection.getResponseMessage())
                .thenReturn("Infernal Server Error");
        when(mockUrlConnection.getOutputStream())
                .thenReturn(new ByteArrayOutputStream());

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            fail("Expected to fail");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), is("HTTP 500: Infernal Server Error"));
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection, atLeastOnce()).getResponseMessage();
    }

    /**
     * Test GET requests.
     */
    @Test
    public void testSendRequest() throws Exception {
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public String getNonce() {
                return null;
            }
        }) {
            conn.sendRequest(requestUrl, session);
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
     * Test signed POST requests.
     */
    @Test
    public void testSendSignedRequest() throws Exception {
        final String nonce1 = Base64Url.encode("foo-nonce-1-foo".getBytes());
        final String nonce2 = Base64Url.encode("foo-nonce-2-foo".getBytes());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void resetNonce(Session session) {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == null) {
                    session.setNonce(nonce1);
                } else {
                    fail("unknown nonce");
                }
            }

            @Override
            public String getNonce() {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == nonce1) {
                    return nonce2;
                } else {
                    fail("unknown nonce");
                    return null;
                }
            }
        }) {
            JSONBuilder cb = new JSONBuilder();
            cb.put("foo", 123).put("bar", "a-string");
            conn.sendSignedRequest(requestUrl, cb, login);
        }

        verify(mockUrlConnection).setRequestMethod("POST");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/json");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setRequestProperty("Content-Type", "application/jose+json");
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).setDoOutput(true);
        verify(mockUrlConnection).setFixedLengthStreamingMode(outputStream.toByteArray().length);
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getOutputStream();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);

        JSON data = JSON.parse(new String(outputStream.toByteArray(), "utf-8"));
        String encodedHeader = data.get("protected").asString();
        String encodedSignature = data.get("signature").asString();
        String encodedPayload = data.get("payload").asString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(accountUrl).append('"');
        expectedHeader.append('}');

        assertThat(Base64Url.decodeToUtf8String(encodedHeader), sameJSONAs(expectedHeader.toString()));
        assertThat(Base64Url.decodeToUtf8String(encodedPayload), sameJSONAs("{\"foo\":123,\"bar\":\"a-string\"}"));
        assertThat(encodedSignature, not(isEmptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test signed POST-as-GET requests.
     */
    @Test
    public void testSendSignedPostAsGetRequest() throws Exception {
        final String nonce1 = Base64Url.encode("foo-nonce-1-foo".getBytes());
        final String nonce2 = Base64Url.encode("foo-nonce-2-foo".getBytes());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void resetNonce(Session session) {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == null) {
                    session.setNonce(nonce1);
                } else {
                    fail("unknown nonce");
                }
            }

            @Override
            public String getNonce() {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == nonce1) {
                    return nonce2;
                } else {
                    fail("unknown nonce");
                    return null;
                }
            }
        }) {
            conn.sendSignedPostAsGetRequest(requestUrl, login);
        }

        verify(mockUrlConnection).setRequestMethod("POST");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/json");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setRequestProperty("Content-Type", "application/jose+json");
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).setDoOutput(true);
        verify(mockUrlConnection).setFixedLengthStreamingMode(outputStream.toByteArray().length);
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getOutputStream();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);

        JSON data = JSON.parse(new String(outputStream.toByteArray(), "utf-8"));
        String encodedHeader = data.get("protected").asString();
        String encodedSignature = data.get("signature").asString();
        String encodedPayload = data.get("payload").asString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(accountUrl).append('"');
        expectedHeader.append('}');

        assertThat(Base64Url.decodeToUtf8String(encodedHeader), sameJSONAs(expectedHeader.toString()));
        assertThat(Base64Url.decodeToUtf8String(encodedPayload), is(""));
        assertThat(encodedSignature, not(isEmptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test certificate POST-as-GET requests.
     */
    @Test
    public void testSendCertificateRequest() throws Exception {
        final String nonce1 = Base64Url.encode("foo-nonce-1-foo".getBytes());
        final String nonce2 = Base64Url.encode("foo-nonce-2-foo".getBytes());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void resetNonce(Session session) {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == null) {
                    session.setNonce(nonce1);
                } else {
                    fail("unknown nonce");
                }
            }

            @Override
            public String getNonce() {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == nonce1) {
                    return nonce2;
                } else {
                    fail("unknown nonce");
                    return null;
                }
            }
        }) {
            conn.sendCertificateRequest(requestUrl, login);
        }

        verify(mockUrlConnection).setRequestMethod("POST");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/pem-certificate-chain");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setRequestProperty("Content-Type", "application/jose+json");
        verify(mockUrlConnection).setDoOutput(true);
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).setFixedLengthStreamingMode(outputStream.toByteArray().length);
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getOutputStream();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test signed POST requests without KeyIdentifier.
     */
    @Test
    public void testSendSignedRequestNoKid() throws Exception {
        final String nonce1 = Base64Url.encode("foo-nonce-1-foo".getBytes());
        final String nonce2 = Base64Url.encode("foo-nonce-2-foo".getBytes());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void resetNonce(Session session) {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == null) {
                    session.setNonce(nonce1);
                } else {
                    fail("unknown nonce");
                }
            }

            @Override
            public String getNonce() {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == nonce1) {
                    return nonce2;
                } else {
                    fail("unknown nonce");
                    return null;
                }
            }
        }) {
            JSONBuilder cb = new JSONBuilder();
            cb.put("foo", 123).put("bar", "a-string");
            conn.sendSignedRequest(requestUrl, cb, session, keyPair);
        }

        verify(mockUrlConnection).setRequestMethod("POST");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/json");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Accept-Language", "ja-JP");
        verify(mockUrlConnection).setRequestProperty("Content-Type", "application/jose+json");
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).setDoOutput(true);
        verify(mockUrlConnection).setFixedLengthStreamingMode(outputStream.toByteArray().length);
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getOutputStream();
        verify(mockUrlConnection, atLeast(0)).getHeaderFields();
        verifyNoMoreInteractions(mockUrlConnection);

        JSON data = JSON.parse(new String(outputStream.toByteArray(), "utf-8"));
        String encodedHeader = data.get("protected").asString();
        String encodedSignature = data.get("signature").asString();
        String encodedPayload = data.get("payload").asString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\":{");
        expectedHeader.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
        expectedHeader.append("\"e\":\"").append(TestUtils.E).append("\",");
        expectedHeader.append("\"n\":\"").append(TestUtils.N).append("\"");
        expectedHeader.append("}}");

        assertThat(Base64Url.decodeToUtf8String(encodedHeader), sameJSONAs(expectedHeader.toString()));
        assertThat(Base64Url.decodeToUtf8String(encodedPayload), sameJSONAs("{\"foo\":123,\"bar\":\"a-string\"}"));
        assertThat(encodedSignature, not(isEmptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test signed POST requests if there is no nonce.
     */
    @Test(expected = AcmeException.class)
    public void testSendSignedRequestNoNonce() throws Exception {
        when(mockHttpConnection.openConnection(new URL("https://example.com/acme/new-nonce"), Proxy.NO_PROXY))
                .thenReturn(mockUrlConnection);
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_NOT_FOUND);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            JSONBuilder cb = new JSONBuilder();
            conn.sendSignedRequest(requestUrl, cb, DefaultConnectionTest.this.session, DefaultConnectionTest.this.keyPair);
        }
    }

    /**
     * Test getting a JSON response.
     */
    @Test
    public void testReadJsonResponse() throws Exception {
        String jsonData = "{\n\"foo\":123,\n\"bar\":\"a-string\"\n}\n";

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/json");
        when(mockUrlConnection.getContentLength()).thenReturn(jsonData.length());
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            JSON result = conn.readJsonResponse();
            assertThat(result, is(notNullValue()));
            assertThat(result.keySet(), hasSize(2));
            assertThat(result.get("foo").asInt(), is(123));
            assertThat(result.get("bar").asString(), is("a-string"));
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection).getContentLength();
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getInputStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that a certificate is downloaded correctly.
     */
    @Test
    public void testReadCertificate() throws Exception {
        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/pem-certificate-chain");
        when(mockUrlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/cert.pem"));

        List<X509Certificate> downloaded;
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            downloaded = conn.readCertificates();
        }

        List<X509Certificate> original = TestUtils.createCertificate();
        assertThat(original.size(), is(2));

        assertThat(downloaded, not(nullValue()));
        assertThat(downloaded.size(), is(original.size()));
        for (int ix = 0; ix < downloaded.size(); ix++) {
            assertThat(downloaded.get(ix).getEncoded(), is(original.get(ix).getEncoded()));
        };

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection).getInputStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that a bad certificate throws an exception.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testReadBadCertificate() throws Exception {
        // Build a broken certificate chain PEM file
        byte[] brokenPem;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        OutputStreamWriter w = new OutputStreamWriter(baos)) {
            for (X509Certificate cert : TestUtils.createCertificate()) {
                byte[] badCert = cert.getEncoded();
                Arrays.sort(badCert); // break it
                AcmeUtils.writeToPem(badCert, AcmeUtils.PemLabel.CERTIFICATE, w);
            }
            w.flush();
            brokenPem = baos.toByteArray();
        }

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/pem-certificate-chain");
        when(mockUrlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(brokenPem));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.readCertificates();
        }
    }

}
