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

import static java.util.stream.Collectors.toList;
import static org.shredzone.acme4j.toolbox.AcmeUtils.keyAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link Connection}.
 */
@ParametersAreNonnullByDefault
public class DefaultConnection implements Connection {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConnection.class);

    private static final String ACCEPT_HEADER = "Accept";
    private static final String ACCEPT_CHARSET_HEADER = "Accept-Charset";
    private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String DATE_HEADER = "Date";
    private static final String LINK_HEADER = "Link";
    private static final String LOCATION_HEADER = "Location";
    private static final String REPLAY_NONCE_HEADER = "Replay-Nonce";
    private static final String RETRY_AFTER_HEADER = "Retry-After";
    private static final String DEFAULT_CHARSET = "utf-8";

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("[0-9A-Za-z_-]+");

    private static final URI BAD_NONCE_ERROR = URI.create("urn:ietf:params:acme:error:badNonce");
    private static final int MAX_ATTEMPTS = 10;

    protected final HttpConnector httpConnector;
    protected HttpURLConnection conn;

    /**
     * Creates a new {@link DefaultConnection}.
     *
     * @param httpConnector
     *            {@link HttpConnector} to be used for HTTP connections
     */
    public DefaultConnection(HttpConnector httpConnector) {
        this.httpConnector = Objects.requireNonNull(httpConnector, "httpConnector");
    }

    @Override
    public void resetNonce(Session session) throws AcmeException {
        assertConnectionIsClosed();

        try {
            session.setNonce(null);

            URL newNonceUrl = session.resourceUrl(Resource.NEW_NONCE);

            conn = httpConnector.openConnection(newNonceUrl, session.getProxy());
            conn.setRequestMethod("HEAD");
            conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
            conn.connect();

            int rc = conn.getResponseCode();
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_NO_CONTENT) {
                throwAcmeException();
            }

            String nonce = getNonce();
            if (nonce == null) {
                throw new AcmeProtocolException("Server did not provide a nonce");
            }
            session.setNonce(nonce);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } finally {
            conn = null;
        }
    }

    @Override
    public void sendRequest(URL url, Session session) throws AcmeException {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(session, "session");
        assertConnectionIsClosed();

        LOG.debug("GET {}", url);

        try {
            conn = httpConnector.openConnection(url, session.getProxy());
            conn.setRequestMethod("GET");
            conn.setRequestProperty(ACCEPT_CHARSET_HEADER, DEFAULT_CHARSET);
            conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
            conn.setDoOutput(false);

            conn.connect();

            logHeaders();

            int rc = conn.getResponseCode();
            if (rc != HttpURLConnection.HTTP_OK) {
                throwAcmeException();
            }

        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
        return sendSignedRequest(url, claims, login.getSession(), login.getKeyPair(), login.getAccountLocation());
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair)
                throws AcmeException {
        return sendSignedRequest(url, claims, session, keypair, null);
    }

    private int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair, @Nullable URL accountLocation)
                throws AcmeException {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(claims, "claims");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(keypair, "keypair");
        assertConnectionIsClosed();

        AcmeException lastException = null;

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return performRequest(url, claims, session, keypair, accountLocation);
            } catch (AcmeServerException ex) {
                if (!BAD_NONCE_ERROR.equals(ex.getType())) {
                    throw ex;
                }
                lastException = ex;
                LOG.info("Bad Replay Nonce, trying again (attempt {}/{})", attempt, MAX_ATTEMPTS);
            }
        }

        throw new AcmeException("Too many reattempts", lastException);
    }

    @Override
    @CheckForNull
    public JSON readJsonResponse() throws AcmeException {
        assertConnectionIsOpen();

        if (conn.getContentLength() == 0) {
            return null;
        }

        String contentType = AcmeUtils.getContentType(conn.getHeaderField(CONTENT_TYPE_HEADER));
        if (!("application/json".equals(contentType)
                    || "application/problem+json".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        JSON result = null;

        try {
            InputStream in =
                    conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream();
            if (in != null) {
                result = JSON.parse(in);
                LOG.debug("Result JSON: {}", result.toString());
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }

        return result;
    }

    @Override
    public List<X509Certificate> readCertificates() throws AcmeException {
        assertConnectionIsOpen();

        String contentType = AcmeUtils.getContentType(conn.getHeaderField(CONTENT_TYPE_HEADER));
        if (!("application/pem-certificate-chain".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        try (InputStream in = conn.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificates(in).stream()
                    .map(c -> (X509Certificate) c)
                    .collect(toList());
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } catch (CertificateException ex) {
            throw new AcmeProtocolException("Failed to read certificate", ex);
        }
    }

    @Override
    public void handleRetryAfter(String message) throws AcmeException {
        assertConnectionIsOpen();

        Optional<Instant> retryAfter = getRetryAfterHeader();
        if (retryAfter.isPresent()) {
            throw new AcmeRetryAfterException(message, retryAfter.get());
        }
    }

    @Override
    @CheckForNull
    public String getNonce() {
        assertConnectionIsOpen();

        String nonceHeader = conn.getHeaderField(REPLAY_NONCE_HEADER);
        if (nonceHeader == null || nonceHeader.trim().isEmpty()) {
            return null;
        }

        if (!BASE64URL_PATTERN.matcher(nonceHeader).matches()) {
            throw new AcmeProtocolException("Invalid replay nonce: " + nonceHeader);
        }

        LOG.debug("Replay Nonce: {}", nonceHeader);

        return nonceHeader;
    }

    @Override
    @CheckForNull
    public URL getLocation() {
        assertConnectionIsOpen();

        String location = conn.getHeaderField(LOCATION_HEADER);
        if (location == null) {
            return null;
        }

        LOG.debug("Location: {}", location);
        return resolveRelative(location);
    }

    @Override
    public Collection<URL> getLinks(String relation) {
        return collectLinks(relation).stream()
                .map(this::resolveRelative)
                .collect(toList());
    }

    @Override
    public void close() {
        conn = null;
    }

    /**
     * Performs the POST request.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims. Must not be {@code null}.
     * @param session
     *            {@link Session} instance to be used for signing and tracking
     * @param keypair
     *            {@link KeyPair} to be used for signing
     * @param accountLocation
     *            If set, the account location is set as "kid" header. If {@code null},
     *            the public key is set as "jwk" header.
     * @return HTTP 200 class status that was returned
     */
    private int performRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair,
                @Nullable URL accountLocation)
                throws AcmeException {
        try {
            if (session.getNonce() == null) {
                resetNonce(session);
            }

            conn = httpConnector.openConnection(url, session.getProxy());
            conn.setRequestMethod("POST");
            conn.setRequestProperty(ACCEPT_HEADER, "application/json");
            conn.setRequestProperty(ACCEPT_CHARSET_HEADER, DEFAULT_CHARSET);
            conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
            conn.setRequestProperty(CONTENT_TYPE_HEADER, "application/jose+json");
            conn.setDoOutput(true);

            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toString());
            jws.getHeaders().setObjectHeaderValue("nonce", session.getNonce());
            jws.getHeaders().setObjectHeaderValue("url", url);
            if (accountLocation == null) {
                jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            } else {
                jws.getHeaders().setObjectHeaderValue("kid", accountLocation);
            }

            jws.setAlgorithmHeaderValue(keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            jws.sign();

            if (LOG.isDebugEnabled()) {
                LOG.debug("POST {}", url);
                LOG.debug("  Payload: {}", claims.toString());
                LOG.debug("  JWS Header: {}", jws.getHeaders().getFullHeaderAsJsonString());
            }

            JSONBuilder jb = new JSONBuilder();
            jb.put("protected", jws.getHeaders().getEncodedHeader());
            jb.put("payload", jws.getEncodedPayload());
            jb.put("signature", jws.getEncodedSignature());
            byte[] outputData = jb.toString().getBytes(DEFAULT_CHARSET);

            conn.setFixedLengthStreamingMode(outputData.length);
            conn.connect();

            try (OutputStream out = conn.getOutputStream()) {
                out.write(outputData);
            }

            logHeaders();

            session.setNonce(getNonce());

            int rc = conn.getResponseCode();
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_CREATED) {
                throwAcmeException();
            }
            return rc;
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to generate a JSON request", ex);
        }
    }

    /**
     * Gets the instant sent with the Retry-After header.
     */
    private Optional<Instant> getRetryAfterHeader() {
        // See RFC 2616 section 14.37
        String header = conn.getHeaderField(RETRY_AFTER_HEADER);
        if (header != null) {
            try {
                // delta-seconds
                if (header.matches("^\\d+$")) {
                    int delta = Integer.parseInt(header);
                    long date = conn.getHeaderFieldDate(DATE_HEADER, System.currentTimeMillis());
                    return Optional.of(Instant.ofEpochMilli(date).plusSeconds(delta));
                }

                // HTTP-date
                long date = conn.getHeaderFieldDate(RETRY_AFTER_HEADER, 0L);
                if (date != 0) {
                    return Optional.of(Instant.ofEpochMilli(date));
                }
            } catch (Exception ex) {
                throw new AcmeProtocolException("Bad retry-after header value: " + header, ex);
            }
        }

        return Optional.empty();
    }

    /**
     * Throws an {@link AcmeException}. This method throws an exception that tries to
     * explain the error as precisely as possible.
     */
    private void throwAcmeException() throws AcmeException {
        try {
            String contentType = AcmeUtils.getContentType(conn.getHeaderField(CONTENT_TYPE_HEADER));
            if (!"application/problem+json".equals(contentType)) {
                throw new AcmeException("HTTP " + conn.getResponseCode() + ": " + conn.getResponseMessage());
            }

            JSON problemJson = readJsonResponse();
            if (problemJson == null) {
                throw new AcmeProtocolException("Empty problem response");
            }
            Problem problem = new Problem(problemJson, conn.getURL());

            String error = AcmeUtils.stripErrorPrefix(problem.getType().toString());

            if ("unauthorized".equals(error)) {
                throw new AcmeUnauthorizedException(problem);
            }

            if ("userActionRequired".equals(error)) {
                URI tos = collectLinks("terms-of-service").stream()
                        .findFirst()
                        .map(this::resolveUri)
                        .orElse(null);
                throw new AcmeUserActionRequiredException(problem, tos);
            }

            if ("rateLimited".equals(error)) {
                Optional<Instant> retryAfter = getRetryAfterHeader();
                Collection<URL> rateLimits = getLinks("urn:ietf:params:acme:documentation");
                throw new AcmeRateLimitedException(problem, retryAfter.orElse(null), rateLimits);
            }

            throw new AcmeServerException(problem);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Asserts that the connection is currently open. Throws an exception if not.
     */
    private void assertConnectionIsOpen() {
        if (conn == null) {
            throw new IllegalStateException("Not connected.");
        }
    }

    /**
     * Asserts that the connection is currently closed. Throws an exception if not.
     */
    private void assertConnectionIsClosed() {
        if (conn != null) {
            throw new IllegalStateException("Previous connection is not closed.");
        }
    }

    /**
     * Log all HTTP headers in debug mode.
     */
    private void logHeaders() {
        if (!LOG.isDebugEnabled()) {
            return;
        }

        conn.getHeaderFields().forEach((key, headers) ->
            headers.forEach(value ->
                LOG.debug("HEADER {}: {}", key, value)
            )
        );
    }

    /**
     * Collects links of the given relation.
     *
     * @param relation
     *            Link relation
     * @return Collection of links, unconverted
     */
    private Collection<String> collectLinks(String relation) {
        assertConnectionIsOpen();

        List<String> result = new ArrayList<>();

        List<String> links = conn.getHeaderFields().get(LINK_HEADER);
        if (links != null) {
            Pattern p = Pattern.compile("<(.*?)>\\s*;\\s*rel=\"?"+ Pattern.quote(relation) + "\"?");
            for (String link : links) {
                Matcher m = p.matcher(link);
                if (m.matches()) {
                    String location = m.group(1);
                    LOG.debug("Link: {} -> {}", relation, location);
                    result.add(location);
                }
            }
        }

        return result;
    }

    /**
     * Resolves a relative link against the connection's last URL.
     *
     * @param link
     *            Link to resolve. Absolute links are just converted to an URL. May be
     *            {@code null}.
     * @return Absolute URL of the given link, or {@code null} if the link was
     *         {@code null}.
     */
    @CheckForNull
    private URL resolveRelative(@Nullable String link) {
        if (link == null) {
            return null;
        }

        assertConnectionIsOpen();
        try {
            return new URL(conn.getURL(), link);
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException("Cannot resolve relative link: " + link, ex);
        }
    }

    /**
     * Resolves a relative URI against the connection's last URL.
     *
     * @param uri
     *            URI to resolve
     * @return Absolute URI of the given link, or {@code null} if the URI was
     *         {@code null}.
     */
    @CheckForNull
    private URI resolveUri(@Nullable String uri) {
        if (uri == null) {
            return null;
        }

        try {
            return conn.getURL().toURI().resolve(uri);
        } catch (URISyntaxException ex) {
            throw new AcmeProtocolException("Invalid URI", ex);
        }
    }

}
