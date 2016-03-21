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
package org.shredzone.acme4j.impl;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwx.CompactSerializer;
import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Connection}.
 *
 * @author Richard "Shred" Körber
 */
public class DefaultConnectionTest {

    private URI requestUri;
    private HttpURLConnection mockUrlConnection;
    private HttpConnector mockHttpConnection;

    @Before
    public void setup() throws IOException, URISyntaxException {
        requestUri = new URI("http://example.com/acme/");

        mockUrlConnection = mock(HttpURLConnection.class);

        mockHttpConnection = mock(HttpConnector.class);
        when(mockHttpConnection.openConnection(requestUri)).thenReturn(mockUrlConnection);
    }

    /**
     * Test if {@link DefaultConnection#updateSession(Session)} does nothing if there is
     * no {@code Replay-Nonce} header.
     */
    @Test
    public void testNoNonceFromHeader() throws AcmeException {
        when(mockUrlConnection.getHeaderField("Replay-Nonce")).thenReturn(null);

        Session session = new Session();
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

        Session session = new Session();
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

        Session session = new Session();
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
     * Test that a Location header is evaluated.
     */
    @Test
    public void testGetLocation() throws Exception {
        when(mockUrlConnection.getHeaderField("Location")).thenReturn("http://example.com/otherlocation");

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            URI location = conn.getLocation();
            assertThat(location, is(new URI("http://example.com/otherlocation")));
        }

        verify(mockUrlConnection).getHeaderField("Location");
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test that Link headers are evaluated.
     */
    @Test
    public void testGetLink() throws Exception {
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        headers.put("Content-Type", Arrays.asList("application/json"));
        headers.put("Location", Arrays.asList("https://example.com/acme/reg/asdf"));
        headers.put("Link", Arrays.asList(
                        "<https://example.com/acme/new-authz>;rel=\"next\"",
                        "<https://example.com/acme/recover-reg>;rel=recover",
                        "<https://example.com/acme/terms>; rel=\"terms-of-service\""
                    ));

        when(mockUrlConnection.getHeaderFields()).thenReturn(headers);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            assertThat(conn.getLink("next"), is(new URI("https://example.com/acme/new-authz")));
            assertThat(conn.getLink("recover"), is(new URI("https://example.com/acme/recover-reg")));
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
        verify(mockUrlConnection).getResponseCode();
        verify(mockUrlConnection).getErrorStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on another problem.
     */
    @Test
    public void testOtherThrowException() {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public Map<String,Object> readJsonResponse() {
                Map<String, Object> result = new HashMap<String, Object>();
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
        verifyNoMoreInteractions(mockUrlConnection);
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is no error type.
     */
    @Test
    public void testNoTypeThrowException() {
        when(mockUrlConnection.getHeaderField("Content-Type"))
                .thenReturn("application/problem+json");

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public Map<String,Object> readJsonResponse() {
                return new HashMap<String, Object>();
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
        final Session testSession = new Session();
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockUrlConnection.getOutputStream()).thenReturn(outputStream);

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection) {
            @Override
            public void updateSession(Session session) {
                assertThat(session, is(sameInstance(testSession)));
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

            KeyPair keypair = TestUtils.createKeyPair();
            Registration reg = new Registration(keypair);

            conn.sendSignedRequest(requestUri, cb, testSession, reg);
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
        String jsonData = "{\"foo\":123,\"bar\":\"a-string\"}";

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

    /**
     * Test if a resource directory is read correctly.
     */
    @Test
    public void testReadDirectory() throws Exception {
        StringBuilder jsonData = new StringBuilder();
        jsonData.append('{');
        jsonData.append("\"new-reg\":\"http://example.com/acme/newreg\",");
        jsonData.append("\"new-authz\":\"http://example.com/acme/newauthz\",");
        jsonData.append("\"old-foo\":\"http://example.com/acme/oldfoo\"");
        jsonData.append('}');

        when(mockUrlConnection.getHeaderField("Content-Type")).thenReturn("application/json");
        when(mockUrlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(jsonData.toString().getBytes("utf-8")));

        try (DefaultConnection conn = new DefaultConnection(mockHttpConnection)) {
            conn.conn = mockUrlConnection;
            Map<Resource, URI> result = conn.readDirectory();
            assertThat(result.keySet(), hasSize(2));
            assertThat(result, hasEntry(Resource.NEW_REG, new URI("http://example.com/acme/newreg")));
            assertThat(result, hasEntry(Resource.NEW_AUTHZ, new URI("http://example.com/acme/newauthz")));
            // "old-foo" resource is unknown and thus not available in the map
        }

        verify(mockUrlConnection).getHeaderField("Content-Type");
        verify(mockUrlConnection).getInputStream();
        verifyNoMoreInteractions(mockUrlConnection);
    }

}
