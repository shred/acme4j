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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.SECONDS;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.getResourceAsByteArray;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link DefaultConnection}.
 */
@WireMockTest
public class DefaultConnectionTest {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC);
    private static final String DIRECTORY_PATH = "/dir";
    private static final String NEW_NONCE_PATH = "/newNonce";
    private static final String REQUEST_PATH = "/test/test";
    private static final String TEST_ACCEPT_LANGUAGE = "ja-JP,ja;q=0.8,*;q=0.1";
    private static final String TEST_ACCEPT_CHARSET = "utf-8";
    private static final String TEST_USER_AGENT_PATTERN = "^acme4j/.*$";

    private final URL accountUrl = TestUtils.url(TestUtils.ACCOUNT_URL);
    private Session session;
    private Login login;
    private KeyPair keyPair;
    private String baseUrl;
    private URL directoryUrl;
    private URL newNonceUrl;
    private URL requestUrl;

    @BeforeEach
    public void setup(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        directoryUrl = URI.create(baseUrl + DIRECTORY_PATH).toURL();
        newNonceUrl = URI.create(baseUrl + NEW_NONCE_PATH).toURL();
        requestUrl = URI.create(baseUrl + REQUEST_PATH).toURL();

        session = new Session(directoryUrl.toURI());
        session.setLocale(Locale.JAPAN);

        keyPair = TestUtils.createKeyPair();

        login = session.login(accountUrl, keyPair);

        var directory = new JSONBuilder();
        directory.put("newNonce", newNonceUrl);

        stubFor(get(DIRECTORY_PATH).willReturn(okJson(directory.toString())));
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} is empty if there is no
     * {@code Replay-Nonce} header.
     */
    @Test
    public void testNoNonceFromHeader() throws AcmeException {
        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()));

        assertThat(session.getNonce()).isNull();

        try (var conn = session.connect()) {
            conn.sendRequest(directoryUrl, session, null);
            assertThat(conn.getNonce()).isEmpty();
        }
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} extracts a {@code Replay-Nonce}
     * header correctly.
     */
    @Test
    public void testGetNonceFromHeader() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", TestUtils.DUMMY_NONCE)
        ));

        assertThat(session.getNonce()).isNull();

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getNonce().orElseThrow()).isEqualTo(TestUtils.DUMMY_NONCE);
            assertThat(session.getNonce()).isEqualTo(TestUtils.DUMMY_NONCE);
        }

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH)));
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} handles fails correctly.
     */
    @Test
    public void testGetNonceFromHeaderFailed() throws AcmeException {
        var retryAfter = Instant.now().plusSeconds(30L).truncatedTo(SECONDS);

        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_UNAVAILABLE)
                .withHeader("Content-Type", "application/problem+json")
                // do not send a body here because it is a HEAD request!
        ));

        assertThat(session.getNonce()).isNull();

        assertThatExceptionOfType(AcmeException.class).isThrownBy(() -> {
            try (var conn = session.connect()) {
                conn.resetNonce(session);
            }
        });

        verify(headRequestedFor(urlEqualTo(NEW_NONCE_PATH)));
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} handles a general HTTP error
     * correctly.
     */
    @Test
    public void testGetNonceFromHeaderHttpError() {
        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_INTERNAL_ERROR)
                // do not send a body here because it is a HEAD request!
        ));

        assertThat(session.getNonce()).isNull();

        var ex = assertThrows(AcmeException.class, () -> {
            try (var conn = session.connect()) {
                conn.resetNonce(session);
            }
        });
        assertThat(ex.getMessage()).isEqualTo("Server responded with HTTP 500 while trying to retrieve a nonce");

        verify(headRequestedFor(urlEqualTo(NEW_NONCE_PATH)));
    }

    /**
     * Test that {@link DefaultConnection#getNonce()} fails on an invalid
     * {@code Replay-Nonce} header.
     */
    @Test
    public void testInvalidNonceFromHeader() {
        var badNonce = "#$%&/*+*#'";

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", badNonce)
        ));

        var ex = assertThrows(AcmeProtocolException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendRequest(requestUrl, session, null);
                conn.getNonce();
            }
        });
        assertThat(ex.getMessage()).startsWith("Invalid replay nonce");

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH)));
    }

    /**
     * Test that {@link DefaultConnection#resetNonce(Session)} fetches a new nonce via
     * new-nonce resource and a HEAD request.
     */
    @Test
    public void testResetNonceSucceedsIfNoncePresent() throws AcmeException {
        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", TestUtils.DUMMY_NONCE)
        ));

        assertThat(session.getNonce()).isNull();

        try (var conn = session.connect()) {
            conn.resetNonce(session);
        }

        assertThat(session.getNonce()).isEqualTo(TestUtils.DUMMY_NONCE);
    }

    /**
     * Test that {@link DefaultConnection#resetNonce(Session)} throws an exception if
     * there is no nonce header.
     */
    @Test
    public void testResetNonceThrowsException() {
        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()));

        assertThat(session.getNonce()).isNull();

        assertThrows(AcmeProtocolException.class, () -> {
            try (var conn = session.connect()) {
                conn.resetNonce(session);
            }
        });

        assertThat(session.getNonce()).isNull();
    }

    /**
     * Test that an absolute Location header is evaluated.
     */
    @Test
    public void testGetAbsoluteLocation() throws Exception {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Location", "https://example.com/otherlocation")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            var location = conn.getLocation();
            assertThat(location).isEqualTo(URI.create("https://example.com/otherlocation").toURL());
        }
    }

    /**
     * Test that a relative Location header is evaluated.
     */
    @Test
    public void testGetRelativeLocation() throws Exception {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Location", "/otherlocation")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            var location = conn.getLocation();
            assertThat(location).isEqualTo(URI.create(baseUrl + "/otherlocation").toURL());
        }
    }

    /**
     * Test that absolute and relative Link headers are evaluated.
     */
    @Test
    public void testGetLink() throws Exception {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Link", "<https://example.com/acme/new-authz>;rel=\"next\"")
                .withHeader("Link", "</recover-acct>;rel=recover")
                .withHeader("Link", "<https://example.com/acme/terms>; rel=\"terms-of-service\"")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getLinks("next")).containsExactly(URI.create("https://example.com/acme/new-authz").toURL());
            assertThat(conn.getLinks("recover")).containsExactly(URI.create(baseUrl + "/recover-acct").toURL());
            assertThat(conn.getLinks("terms-of-service")).containsExactly(URI.create("https://example.com/acme/terms").toURL());
            assertThat(conn.getLinks("secret-stuff")).isEmpty();
        }
    }

    /**
     * Test that multiple link headers are evaluated.
     */
    @Test
    public void testGetMultiLink() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Link", "<https://example.com/acme/terms1>; rel=\"terms-of-service\"")
                .withHeader("Link", "<https://example.com/acme/terms2>; rel=\"terms-of-service\"")
                .withHeader("Link", "<../terms3>; rel=\"terms-of-service\"")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getLinks("terms-of-service")).containsExactlyInAnyOrder(
                    url("https://example.com/acme/terms1"),
                    url("https://example.com/acme/terms2"),
                    url(baseUrl + "/terms3")
            );
        }
    }

    /**
     * Test that no link headers are properly handled.
     */
    @Test
    public void testGetNoLink() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getLinks("something")).isEmpty();
        }
    }

    /**
     * Test that no Location header returns {@code null}.
     */
    @Test
    public void testNoLocation() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThatExceptionOfType(AcmeProtocolException.class)
                    .isThrownBy(conn::getLocation);
        }

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH)));
    }

    /**
     * Test if Retry-After header with absolute date is correctly parsed.
     */
    @Test
    public void testHandleRetryAfterHeaderDate() throws AcmeException {
        var retryDate = Instant.now().plus(Duration.ofHours(10)).truncatedTo(SECONDS);

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Retry-After", DATE_FORMATTER.format(retryDate))
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getRetryAfter()).hasValue(retryDate);
        }
    }

    /**
     * Test if Retry-After header with relative timespan is correctly parsed.
     */
    @Test
    public void testHandleRetryAfterHeaderDelta() throws AcmeException {
        var delta = 10 * 60 * 60;
        var now = Instant.now().truncatedTo(SECONDS);
        var retryMsg = "relative time";

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Retry-After", String.valueOf(delta))
                .withHeader("Date", DATE_FORMATTER.format(now))
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getRetryAfter()).hasValue(now.plusSeconds(delta));
        }
    }

    /**
     * Test if no Retry-After header is correctly handled.
     */
    @Test
    public void testHandleRetryAfterHeaderNull() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Date", DATE_FORMATTER.format(Instant.now()))
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getRetryAfter()).isEmpty();
        }

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH)));
    }

    /**
     * Test if no exception is thrown on a standard request.
     */
    @Test
    public void testAccept() throws AcmeException {
        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withBody("")
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        try (var conn = session.connect()) {
            var rc = conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            assertThat(rc).isEqualTo(HttpURLConnection.HTTP_OK);
        }

        verify(postRequestedFor(urlEqualTo(REQUEST_PATH)));
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsException() {
        var problem = new JSONBuilder();
        problem.put("type", "urn:ietf:params:acme:error:unauthorized");
        problem.put("detail", "Invalid response: 404");

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_FORBIDDEN)
                .withHeader("Content-Type", "application/problem+json")
                .withBody(problem.toString())
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });

        assertThat(ex).isInstanceOf(AcmeUnauthorizedException.class);
        assertThat(((AcmeUnauthorizedException) ex).getType())
                .isEqualTo(URI.create("urn:ietf:params:acme:error:unauthorized"));
        assertThat(ex.getMessage()).isEqualTo("Invalid response: 404");
    }

    /**
     * Test if an {@link AcmeUserActionRequiredException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsUserActionRequiredException() {
        var problem = new JSONBuilder();
        problem.put("type", "urn:ietf:params:acme:error:userActionRequired");
        problem.put("detail", "Accept the TOS");

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_FORBIDDEN)
                .withHeader("Content-Type", "application/problem+json")
                .withHeader("Link", "<https://example.com/tos.pdf>; rel=\"terms-of-service\"")
                .withBody(problem.toString())
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });

        assertThat(ex).isInstanceOf(AcmeUserActionRequiredException.class);
        assertThat(((AcmeUserActionRequiredException) ex).getType())
                .isEqualTo(URI.create("urn:ietf:params:acme:error:userActionRequired"));
        assertThat(ex.getMessage()).isEqualTo("Accept the TOS");
        assertThat(((AcmeUserActionRequiredException) ex).getTermsOfServiceUri().orElseThrow())
                .isEqualTo(URI.create("https://example.com/tos.pdf"));
    }

    /**
     * Test if an {@link AcmeRateLimitedException} is thrown on an acme problem.
     */
    @Test
    public void testAcceptThrowsRateLimitedException() {
        var problem = new JSONBuilder();
        problem.put("type", "urn:ietf:params:acme:error:rateLimited");
        problem.put("detail", "Too many invocations");

        var retryAfter = Instant.now().plusSeconds(30L).truncatedTo(SECONDS);

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_FORBIDDEN)
                .withHeader("Content-Type", "application/problem+json")
                .withHeader("Link", "<https://example.com/rates.pdf>; rel=\"help\"")
                .withHeader("Retry-After", DATE_FORMATTER.format(retryAfter))
                .withBody(problem.toString())
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeRateLimitedException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });

        assertThat(ex.getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:rateLimited"));
        assertThat(ex.getMessage()).isEqualTo("Too many invocations");
        assertThat(ex.getRetryAfter().orElseThrow()).isEqualTo(retryAfter);
        assertThat(ex.getDocuments()).isNotNull();
        assertThat(ex.getDocuments()).hasSize(1);
        assertThat(ex.getDocuments().iterator().next()).isEqualTo(url("https://example.com/rates.pdf"));
    }

    /**
     * Test if an {@link AcmeServerException} is thrown on another problem.
     */
    @Test
    public void testAcceptThrowsOtherException() {
        var problem = new JSONBuilder();
        problem.put("type", "urn:zombie:error:apocalypse");
        problem.put("detail", "Zombie apocalypse in progress");

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_INTERNAL_ERROR)
                .withHeader("Content-Type", "application/problem+json")
                .withBody(problem.toString())
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeServerException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });

        assertThat(ex.getType()).isEqualTo(URI.create("urn:zombie:error:apocalypse"));
        assertThat(ex.getMessage()).isEqualTo("Zombie apocalypse in progress");
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is no error type.
     */
    @Test
    public void testAcceptThrowsNoTypeException() {
        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_INTERNAL_ERROR)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("{}")
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeProtocolException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });
        assertThat(ex.getMessage()).isNotEmpty();
    }

    /**
     * Test if an {@link AcmeException} is thrown if there is a generic error.
     */
    @Test
    public void testAcceptThrowsServerException() {
        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_INTERNAL_ERROR)
                .withStatusMessage("Infernal Server Error")
                .withHeader("Content-Type", "text/html")
                .withBody("<html><head><title>Infernal Server Error</title></head></html>")
        ));

        session.setNonce(TestUtils.DUMMY_NONCE);

        var ex = assertThrows(AcmeException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), login);
            }
        });
        assertThat(ex.getMessage()).isEqualTo("HTTP 500");
    }

    /**
     * Test GET requests.
     */
    @Test
    public void testSendRequest() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
        }

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("Accept", equalTo("application/json"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );
    }

    /**
     * Test GET requests with If-Modified-Since.
     */
    @Test
    public void testSendRequestIfModifiedSince() throws AcmeException {
        var ifModifiedSince = ZonedDateTime.now(ZoneId.of("UTC")).truncatedTo(SECONDS);

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(aResponse()
                .withStatus(HttpURLConnection.HTTP_NOT_MODIFIED))
        );

        try (var conn = session.connect()) {
            var rc = conn.sendRequest(requestUrl, session, ifModifiedSince);
            assertThat(rc).isEqualTo(HttpURLConnection.HTTP_NOT_MODIFIED);
        }

        verify(getRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("If-Modified-Since", equalToDateTime(ifModifiedSince))
                .withHeader("Accept", equalTo("application/json"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );
    }

    /**
     * Test signed POST requests.
     */
    @Test
    public void testSendSignedRequest() throws Exception {
        var nonce1 = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        var nonce2 = URL_ENCODER.encodeToString("foo-nonce-2-foo".getBytes());

        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce1)));

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce2)
        ));

        try (var conn = session.connect()) {
            var cb = new JSONBuilder();
            cb.put("foo", 123).put("bar", "a-string");
            conn.sendSignedRequest(requestUrl, cb, login);
        }

        assertThat(session.getNonce()).isEqualTo(nonce2);

        verify(postRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("Accept", equalTo("application/json"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );

        var requests = findAll(postRequestedFor(urlEqualTo(REQUEST_PATH)));
        assertThat(requests).hasSize(1);

        var data = JSON.parse(requests.get(0).getBodyAsString());
        var encodedHeader = data.get("protected").asString();
        var encodedSignature = data.get("signature").asString();
        var encodedPayload = data.get("payload").asString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(accountUrl).append('"');
        expectedHeader.append('}');

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8)).isEqualTo(expectedHeader.toString());
        assertThatJson(new String(URL_DECODER.decode(encodedPayload), UTF_8)).isEqualTo("{\"foo\":123,\"bar\":\"a-string\"}");
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test signed POST-as-GET requests.
     */
    @Test
    public void testSendSignedPostAsGetRequest() throws Exception {
        var nonce1 = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        var nonce2 = URL_ENCODER.encodeToString("foo-nonce-2-foo".getBytes());

        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce1)));

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce2)));

        try (var conn = session.connect()) {
            conn.sendSignedPostAsGetRequest(requestUrl, login);
        }

        assertThat(session.getNonce()).isEqualTo(nonce2);

        verify(postRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("Accept", equalTo("application/json"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("Content-Type", equalTo("application/jose+json"))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );

        var requests = findAll(postRequestedFor(urlEqualTo(REQUEST_PATH)));
        assertThat(requests).hasSize(1);

        var data = JSON.parse(requests.get(0).getBodyAsString());
        var encodedHeader = data.get("protected").asString();
        var encodedSignature = data.get("signature").asString();
        var encodedPayload = data.get("payload").asString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(accountUrl).append('"');
        expectedHeader.append('}');

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8)).isEqualTo(expectedHeader.toString());
        assertThat(new String(URL_DECODER.decode(encodedPayload), UTF_8)).isEqualTo("");
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test certificate POST-as-GET requests.
     */
    @Test
    public void testSendCertificateRequest() throws AcmeException {
        var nonce1 = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        var nonce2 = URL_ENCODER.encodeToString("foo-nonce-2-foo".getBytes());

        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce1)));

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce2)));

        try (var conn = session.connect()) {
            conn.sendCertificateRequest(requestUrl, login);
        }

        assertThat(session.getNonce()).isEqualTo(nonce2);

        verify(postRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("Accept", equalTo("application/pem-certificate-chain"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("Content-Type", equalTo("application/jose+json"))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );
    }

    /**
     * Test signed POST requests without KeyIdentifier.
     */
    @Test
    public void testSendSignedRequestNoKid() throws Exception {
        var nonce1 = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        var nonce2 = URL_ENCODER.encodeToString("foo-nonce-2-foo".getBytes());

        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce1)));

        stubFor(post(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Replay-Nonce", nonce2)));

        try (var conn = session.connect()) {
            var cb = new JSONBuilder();
            cb.put("foo", 123).put("bar", "a-string");
            conn.sendSignedRequest(requestUrl, cb, session, keyPair);
        }

        assertThat(session.getNonce()).isEqualTo(nonce2);

        verify(postRequestedFor(urlEqualTo(REQUEST_PATH))
                .withHeader("Accept", equalTo("application/json"))
                .withHeader("Accept-Charset", equalTo(TEST_ACCEPT_CHARSET))
                .withHeader("Accept-Language", equalTo(TEST_ACCEPT_LANGUAGE))
                .withHeader("Content-Type", equalTo("application/jose+json"))
                .withHeader("User-Agent", matching(TEST_USER_AGENT_PATTERN))
        );

        var requests = findAll(postRequestedFor(urlEqualTo(REQUEST_PATH)));
        assertThat(requests).hasSize(1);

        var data = JSON.parse(requests.get(0).getBodyAsString());
        String encodedHeader = data.get("protected").asString();
        String encodedSignature = data.get("signature").asString();
        String encodedPayload = data.get("payload").asString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce1).append("\",");
        expectedHeader.append("\"url\":\"").append(requestUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\":{");
        expectedHeader.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
        expectedHeader.append("\"e\":\"").append(TestUtils.E).append("\",");
        expectedHeader.append("\"n\":\"").append(TestUtils.N).append("\"");
        expectedHeader.append("}}");

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8))
                .isEqualTo(expectedHeader.toString());
        assertThatJson(new String(URL_DECODER.decode(encodedPayload), UTF_8))
                .isEqualTo("{\"foo\":123,\"bar\":\"a-string\"}");
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(login.getKeyPair().getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test signed POST requests if there is no nonce.
     */
    @Test
    public void testSendSignedRequestNoNonce() {
        stubFor(head(urlEqualTo(NEW_NONCE_PATH)).willReturn(notFound()));

        assertThrows(AcmeException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendSignedRequest(requestUrl, new JSONBuilder(), session, keyPair);
            }
        });
    }

    /**
     * Test getting a JSON response.
     */
    @Test
    public void testReadJsonResponse() throws AcmeException {
        var response = new JSONBuilder();
        response.put("foo", 123);
        response.put("bar", "a-string");

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody(response.toString())
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);

            var result = conn.readJsonResponse();
            assertThat(result).isNotNull();
            assertThat(result.keySet()).hasSize(2);
            assertThat(result.get("foo").asInt()).isEqualTo(123);
            assertThat(result.get("bar").asString()).isEqualTo("a-string");
        }
    }

    /**
     * Test that a certificate is downloaded correctly.
     */
    @Test
    public void testReadCertificate() throws Exception {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Content-Type", "application/pem-certificate-chain")
                .withBody(getResourceAsByteArray("/cert.pem"))
        ));

        List<X509Certificate> downloaded;
        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            downloaded = conn.readCertificates();
        }

        var original = TestUtils.createCertificate("/cert.pem");
        assertThat(original).hasSize(2);

        assertThat(downloaded).isNotNull();
        assertThat(downloaded).hasSize(original.size());
        for (var ix = 0; ix < downloaded.size(); ix++) {
            assertThat(downloaded.get(ix).getEncoded()).isEqualTo(original.get(ix).getEncoded());
        }
    }

    /**
     * Test that a bad certificate throws an exception.
     */
    @Test
    public void testReadBadCertificate() throws Exception {
        // Build a broken certificate chain PEM file
        byte[] brokenPem;
        try (var baos = new ByteArrayOutputStream(); var w = new OutputStreamWriter(baos)) {
            for (var cert : TestUtils.createCertificate("/cert.pem")) {
                var badCert = cert.getEncoded();
                Arrays.sort(badCert); // break it
                AcmeUtils.writeToPem(badCert, AcmeUtils.PemLabel.CERTIFICATE, w);
            }
            w.flush();
            brokenPem = baos.toByteArray();
        }

        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Content-Type", "application/pem-certificate-chain")
                .withBody(brokenPem)
        ));

        assertThrows(AcmeProtocolException.class, () -> {
            try (var conn = session.connect()) {
                conn.sendRequest(requestUrl, session, null);
                conn.readCertificates();
            }
        });
    }

    /**
     * Test that {@link DefaultConnection#getLastModified()} returns valid dates.
     */
    @Test
    public void testLastModifiedUnset() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getLastModified().isPresent()).isFalse();
        }
    }

    @Test
    public void testLastModifiedSet() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Last-Modified", "Thu, 07 May 2020 19:42:46 GMT")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);

            var lm = conn.getLastModified();
            assertThat(lm.isPresent()).isTrue();
            assertThat(lm.get().format(DateTimeFormatter.ISO_DATE_TIME))
                    .isEqualTo("2020-05-07T19:42:46Z");
        }
    }

    @Test
    public void testLastModifiedInvalid() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Last-Modified", "iNvAlId")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getLastModified().isPresent()).isFalse();
        }
    }

    /**
     * Test that {@link DefaultConnection#getExpiration()} returns valid dates.
     */
    @Test
    public void testExpirationUnset() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getExpiration().isPresent()).isFalse();
        }
    }

    @Test
    public void testExpirationNoCache() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Cache-Control", "public, no-cache")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getExpiration().isPresent()).isFalse();
        }
    }

    @Test
    public void testExpirationMaxAgeZero() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Cache-Control", "public, max-age=0, no-cache")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getExpiration().isPresent()).isFalse();
        }
    }

    @Test
    public void testExpirationMaxAgeButNoCache() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Cache-Control", "public, max-age=3600, no-cache")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getExpiration().isPresent()).isFalse();
        }
    }

    @Test
    public void testExpirationMaxAge() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Cache-Control", "max-age=3600")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);

            var exp = conn.getExpiration();
            assertThat(exp.isPresent()).isTrue();
            assertThat(exp.get().isAfter(ZonedDateTime.now().plusHours(1).minusMinutes(1))).isTrue();
            assertThat(exp.get().isBefore(ZonedDateTime.now().plusHours(1).plusMinutes(1))).isTrue();
        }
    }

    @Test
    public void testExpirationExpires() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Expires", "Thu, 18 Jun 2020 08:43:04 GMT")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);

            var exp = conn.getExpiration();
            assertThat(exp.isPresent()).isTrue();
            assertThat(exp.get().format(DateTimeFormatter.ISO_DATE_TIME))
                    .isEqualTo("2020-06-18T08:43:04Z");
        }
    }

    @Test
    public void testExpirationInvalidExpires() throws AcmeException {
        stubFor(get(urlEqualTo(REQUEST_PATH)).willReturn(ok()
                .withHeader("Expires", "iNvAlId")
        ));

        try (var conn = session.connect()) {
            conn.sendRequest(requestUrl, session, null);
            assertThat(conn.getExpiration().isPresent()).isFalse();
        }
    }

}
