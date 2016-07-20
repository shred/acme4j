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
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwx.CompactSerializer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link DefaultConnection}.
 *
 * @author Richard "Shred" Körber
 */
public class DefaultConnectionTest {

    private URI requestUri = URI.create("http://example.com/acme/");;
    private HttpURLConnection mockUrlConnection;
    private HttpConnector mockHttpConnection;
    private Session session;

    @Before
    public void setup() throws IOException {
        mockUrlConnection = mock(HttpURLConnection.class);

        mockHttpConnection = mock(HttpConnector.class);
        when(mockHttpConnection.openConnection(requestUri)).thenReturn(mockUrlConnection);

        session = TestUtils.session();
    }

    /**
     * Test if {@link DefaultConnection#updateSession(Session)} does nothing if there is
     * no {@code Replay-Nonce} header.
     */
    @Test
    public void testNoNonceFromHeader() throws AcmeException {
        when(mockUrlConnection.getHeaderField("Replay-Nonce")).thenReturn(null);

        assertThat(session.getNonce(), is(nullValue()));
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.updateSession(session);
        }
        assertThat(session.getNonce(), is(nullValue()));

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that {@link DefaultConnection#updateSession(Session)} extracts a
     * {@code Replay-Nonce} header correctly.
     */
    @Test
    public void testGetNonceFromHeader() {
        byte[] nonce = "foo-nonce-foo".getBytes();

        when(mockUrlConnection.getHeaderField("Replay-Nonce"))
                .thenReturn(Base64Url.encode(nonce));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.updateSession(session);
        }
        assertThat(session.getNonce(), is(nonce));

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that {@link DefaultConnection#updateSession(Session)} fails on an invalid
     * {@code Replay-Nonce} header.
     */
    @Test
    public void testInvalidNonceFromHeader() {
        String badNonce = "#$%&/*+*#'";

        when(mockUrlConnection.getHeaderField("Replay-Nonce")).thenReturn(badNonce);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.updateSession(session);
            fail("Expected to fail");
        } catch (AcmeProtocolException ex) {
            assertThat(ex.getMessage(), org.hamcrest.Matchers.startsWith("Invalid replay nonce"));
        }

        verify(mockUrlConnection).getHeaderField("Replay-Nonce");
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
            URI location = conn.getLocation();
            assertThat(location, is(new URI("https://example.com/otherlocation")));
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
            URI location = conn.getLocation();
            assertThat(location, is(new URI("https://example.org/otherlocation")));
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
        headers.put("Location", Arrays.asList("https://example.com/acme/reg/asdf"));
        headers.put("Link", Arrays.asList(
                        "<https://example.com/acme/new-authz>;rel=\"next\"",
                        "</recover-reg>;rel=recover",
                        "<https://example.com/acme/terms>; rel=\"terms-of-service\""
                    ));

        when(mockUrlConnection.getHeaderFields()).thenReturn(headers);
        when(mockUrlConnection.getURL()).thenReturn(new URL("https://example.org/acme"));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getLink("next"), is(new URI("https://example.com/acme/new-authz")));
            assertThat(conn.getLink("recover"), is(new URI("https://example.org/recover-reg")));
            assertThat(conn.getLink("terms-of-service"), is(new URI("https://example.com/acme/terms")));
            assertThat(conn.getLink("secret-stuff"), is(nullValue()));
        }
    }

    /**
     * Test that no Location header returns {@code null}.
     */
    @Test
    public void testNoLocation() throws Exception {
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            URI location = conn.getLocation();
            assertThat(location, is(nullValue()));
        }

        verify(mockUrlConnection).getHeaderField("Location");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if Retry-After header with absolute date is correctly parsed.
     */
    @Test
    public void testGetRetryAfterHeaderDate() {
        Date retryDate = new Date(System.currentTimeMillis() + 10 * 60 * 60 * 1000L);

        when(mockUrlConnection.getHeaderField("Retry-After")).thenReturn(retryDate.toString());
        when(mockUrlConnection.getHeaderFieldDate("Retry-After", 0L)).thenReturn(retryDate.getTime());

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getRetryAfterHeader(), is(retryDate));
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
    }

    /**
     * Test if Retry-After header with relative timespan is correctly parsed.
     */
    @Test
    public void testGetRetryAfterHeaderDelta() {
        int delta = 10 * 60 * 60;
        long now = System.currentTimeMillis();

        when(mockUrlConnection.getHeaderField("Retry-After"))
                .thenReturn(String.valueOf(delta));
        when(mockUrlConnection.getHeaderFieldDate(
                        ArgumentMatchers.eq("Date"),
                        ArgumentMatchers.anyLong()))
                .thenReturn(now);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getRetryAfterHeader(), is(new Date(now + delta * 1000L)));
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Retry-After");
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on an acme problem.
     */
    @Test
    public void testThrowException() throws Exception {
        String jsonData = "{\"type\":\"urn:ietf:params:acme:error:unauthorized\",\"detail\":\"Invalid response: 404\"}";

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/problem+json");
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_FORBIDDEN);
        when(mockUrlConnection.getErrorStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            conn.throwAcmeException();
            fail("Expected to fail");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is("urn:ietf:params:acme:error:unauthorized"));
            assertThat(ex.getMessage(), is("Invalid response: 404"));
            assertThat(ex.getAcmeErrorType(), is("unauthorized"));
        } catch (AcmeException ex) {
            fail("Expected an AcmeServerException");
        }

        verify(mockUrlConnection, atLeastOnce()).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verify(mockUrlConnection).getErrorStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on another problem.
     */
    @Test
    public void testOtherThrowException() throws IOException {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public Map<String,Object> readJsonResponse() {
                Map<String, Object> result = new HashMap<>();
                result.put("type", "urn:zombie:error:apocalypse");
                result.put("detail", "Zombie apocalypse in progress");
                return result;
            };
        }) {
            conn.conn = mockUrlConnection;
            conn.throwAcmeException();
            fail("Expected to fail");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is("urn:zombie:error:apocalypse"));
            assertThat(ex.getMessage(), is("Zombie apocalypse in progress"));
            assertThat(ex.getAcmeErrorType(), is(nullValue()));
        } catch (AcmeException | IOException ex) {
            fail("Expected an AcmeServerException");
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is no error type.
     */
    @Test
    public void testNoTypeThrowException() throws IOException {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");
        when(mockUrlConnection.getResponseCode())
                .thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public Map<String,Object> readJsonResponse() {
                return new HashMap<>();
            };
        }) {
            conn.conn = mockUrlConnection;
            conn.throwAcmeException();
            fail("Expected to fail");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), not(isEmptyOrNullString()));
        } catch (IOException ex) {
            fail("Expected an AcmeException");
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection, atLeastOnce()).getResponseCode();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test GET requests.
     */
    @Test
    public void testSendRequest() throws Exception {
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.sendRequest(requestUri);
        }

        verify(mockUrlConnection).setRequestMethod("GET");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setDoOutput(false);
        verify(mockUrlConnection).connect();
        verify(mockUrlConnection).getResponseCode();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test signed POST requests.
     */
    @Test
    public void testSendSignedRequest() throws Exception {
        final byte[] nonce1 = "foo-nonce-1-foo".getBytes();
        final byte[] nonce2 = "foo-nonce-2-foo".getBytes();
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void updateSession(Session session) {
                assertThat(session, is(sameInstance(DefaultConnectionTest.this.session)));
                if (session.getNonce() == null) {
                    session.setNonce(nonce1);
                } else if (session.getNonce() == nonce1) {
                    session.setNonce(nonce2);
                } else {
                    fail("unknown nonce");
                }
            };
        }) {
            ClaimBuilder cb = new ClaimBuilder();
            cb.put("foo", 123).put("bar", "a-string");
            conn.sendSignedRequest(requestUri, cb, DefaultConnectionTest.this.session);
        }

        verify(mockUrlConnection).setRequestMethod("HEAD");
        verify(mockUrlConnection, times(2)).connect();

        verify(mockUrlConnection).setRequestMethod("POST");
        verify(mockUrlConnection).setRequestProperty("Accept", "application/json");
        verify(mockUrlConnection).setRequestProperty("Accept-Charset", "utf-8");
        verify(mockUrlConnection).setRequestProperty("Content-Type", "application/json");
        verify(mockUrlConnection).setDoOutput(true);
        verify(mockUrlConnection).setFixedLengthStreamingMode(outputStream.toByteArray().length);
        verify(mockUrlConnection).getOutputStream();
        verify(mockUrlConnection).getResponseCode();
        verifyNoMoreInteractions(mockUrlConnection);

        String[] written = CompactSerializer.deserialize(new String(outputStream.toByteArray(), "utf-8"));
        String header = Base64Url.decodeToUtf8String(written[0]);
        String claims = Base64Url.decodeToUtf8String(written[1]);
        String signature = written[2];

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(Base64Url.encode(nonce1)).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\":{");
        expectedHeader.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
        expectedHeader.append("\"e\":\"").append(TestUtils.E).append("\",");
        expectedHeader.append("\"n\":\"").append(TestUtils.N).append("\"");
        expectedHeader.append("}}");

        assertThat(header, sameJSONAs(expectedHeader.toString()).allowingExtraUnexpectedFields());
        assertThat(claims, sameJSONAs("{\"foo\":123,\"bar\":\"a-string\"}"));
        assertThat(signature, not(isEmptyOrNullString()));
    }

    /**
     * Test getting a JSON response.
     */
    @Test
    public void testReadJsonResponse() throws Exception {
        String jsonData = "{\n\"foo\":123,\n\"bar\":\"a-string\"\n}\n";

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/json");
        when(mockUrlConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockUrlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(jsonData.getBytes("utf-8")));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            Map<String, Object> result = conn.readJsonResponse();
            assertThat(result.keySet(), hasSize(2));
            assertThat(result, hasEntry("foo", (Object) 123L));
            assertThat(result, hasEntry("bar", (Object) "a-string"));
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getInputStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that a certificate is downloaded correctly.
     */
    @Test
    public void testReadCertificate() throws Exception {
        X509Certificate original = TestUtils.createCertificate();

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/pkix-cert");
        when(mockUrlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(original.getEncoded()));

        X509Certificate downloaded;
        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            downloaded = conn.readCertificate();
        }

        assertThat(original, not(nullValue()));
        assertThat(downloaded, not(nullValue()));
        assertThat(original.getEncoded(), is(equalTo(downloaded.getEncoded())));

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection).getInputStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

}
