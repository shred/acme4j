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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeAgreementRequiredException;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitExceededException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link Connection}.
 */
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
    public void sendRequest(URI uri, Session session) throws AcmeException {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(session, "session");
        assertConnectionIsClosed();

        LOG.debug("GET {}", uri);

        try {
            conn = httpConnector.openConnection(uri);
            conn.setRequestMethod("GET");
            conn.setRequestProperty(ACCEPT_CHARSET_HEADER, DEFAULT_CHARSET);
            conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
            conn.setDoOutput(false);

            conn.connect();

            logHeaders();
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) throws AcmeException {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(claims, "claims");
        Objects.requireNonNull(session, "session");
        assertConnectionIsClosed();

        try {
            KeyPair keypair = session.getKeyPair();

            if (session.getNonce() == null) {
                LOG.debug("Getting initial nonce, HEAD {}", uri);
                conn = httpConnector.openConnection(uri);
                conn.setRequestMethod("HEAD");
                conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
                conn.connect();
                updateSession(session);
                conn = null;
            }

            if (session.getNonce() == null) {
                throw new AcmeProtocolException("Server did not provide a nonce");
            }

            LOG.debug("POST {} with claims: {}", uri, claims);

            conn = httpConnector.openConnection(uri);
            conn.setRequestMethod("POST");
            conn.setRequestProperty(ACCEPT_HEADER, "application/json");
            conn.setRequestProperty(ACCEPT_CHARSET_HEADER, DEFAULT_CHARSET);
            conn.setRequestProperty(ACCEPT_LANGUAGE_HEADER, session.getLocale().toLanguageTag());
            conn.setRequestProperty(CONTENT_TYPE_HEADER, "application/jose+json");
            conn.setDoOutput(true);

            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toString());
            jws.getHeaders().setObjectHeaderValue("nonce", Base64Url.encode(session.getNonce()));
            jws.getHeaders().setObjectHeaderValue("url", uri);
            jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            jws.setAlgorithmHeaderValue(keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            jws.sign();

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

            updateSession(session);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to generate a JSON request", ex);
        }
    }

    @Override
    public int accept(int... httpStatus) throws AcmeException {
        assertConnectionIsOpen();

        try {
            int rc = conn.getResponseCode();
            OptionalInt match = Arrays.stream(httpStatus).filter(s -> s == rc).findFirst();
            if (match.isPresent()) {
                return match.getAsInt();
            }

            if (!"application/problem+json".equals(conn.getHeaderField(CONTENT_TYPE_HEADER))) {
                throw new AcmeException("HTTP " + rc + ": " + conn.getResponseMessage());
            }

            JSON json = readJsonResponse();

            if (rc == HttpURLConnection.HTTP_CONFLICT) {
                throw new AcmeConflictException(json.get("detail").asString(), getLocation());
            }

            throw createAcmeException(json);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public JSON readJsonResponse() throws AcmeException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField(CONTENT_TYPE_HEADER);
        if (contentType == null || !(contentType.contains("application/json")
                || contentType.contains("application/problem+json"))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        JSON result = null;

        try {
            InputStream in =
                    conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream();
            if (in != null) {
                result = JSON.parse(in);
                LOG.debug("Result JSON: {}", result);
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }

        return result;
    }

    @Override
    public X509Certificate readCertificate() throws AcmeException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField(CONTENT_TYPE_HEADER);
        if (!("application/pkix-cert".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        try (InputStream in = conn.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } catch (CertificateException ex) {
            throw new AcmeProtocolException("Failed to read certificate", ex);
        }
    }

    @Override
    public void handleRetryAfter(String message) throws AcmeException {
        assertConnectionIsOpen();

        try {
            if (conn.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
                Optional<Instant> retryAfter = getRetryAfterHeader();
                if (retryAfter.isPresent()) {
                    throw new AcmeRetryAfterException(message, retryAfter.get());
                }
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void updateSession(Session session) {
        assertConnectionIsOpen();

        String nonceHeader = conn.getHeaderField(REPLAY_NONCE_HEADER);
        if (nonceHeader == null || nonceHeader.trim().isEmpty()) {
            return;
        }

        if (!BASE64URL_PATTERN.matcher(nonceHeader).matches()) {
            throw new AcmeProtocolException("Invalid replay nonce: " + nonceHeader);
        }

        LOG.debug("Replay Nonce: {}", nonceHeader);

        session.setNonce(Base64Url.decode(nonceHeader));
    }

    @Override
    public URI getLocation() {
        assertConnectionIsOpen();

        String location = conn.getHeaderField(LOCATION_HEADER);
        if (location == null) {
            return null;
        }

        LOG.debug("Location: {}", location);
        return resolveRelative(location);
    }

    @Override
    public URI getLink(String relation) {
        Collection<URI> links = getLinks(relation);
        if (links == null) {
            return null;
        }

        if (links.size() > 1) {
            LOG.debug("Link: {} - using the first of {}", relation, links.size());
        }

        return links.iterator().next();
    }

    @Override
    public Collection<URI> getLinks(String relation) {
        assertConnectionIsOpen();

        List<URI> result = new ArrayList<>();

        List<String> links = conn.getHeaderFields().get(LINK_HEADER);
        if (links != null) {
            Pattern p = Pattern.compile("<(.*?)>\\s*;\\s*rel=\"?"+ Pattern.quote(relation) + "\"?");
            for (String link : links) {
                Matcher m = p.matcher(link);
                if (m.matches()) {
                    String location = m.group(1);
                    LOG.debug("Link: {} -> {}", relation, location);
                    result.add(resolveRelative(location));
                }
            }
        }

        return !result.isEmpty() ? result : null;
    }

    @Override
    public void close() {
        conn = null;
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
     * Handles a problem by throwing an exception. If a JSON problem was returned, an
     * {@link AcmeServerException} or subtype will be thrown. Otherwise a generic
     * {@link AcmeException} is thrown.
     */
    private AcmeException createAcmeException(JSON json) {
        String type = json.get("type").asString();
        String detail = json.get("detail").asString();
        String error = AcmeUtils.stripErrorPrefix(type);

        if (type == null) {
            return new AcmeException(detail);
        }

        if ("unauthorized".equals(error)) {
            return new AcmeUnauthorizedException(type, detail);
        }

        if ("agreementRequired".equals(error)) {
            URI instance = resolveRelative(json.get("instance").asString());
            URI tos = getLink("terms-of-service");
            return new AcmeAgreementRequiredException(type, detail, tos, instance);
        }

        if ("rateLimited".equals(error)) {
            Optional<Instant> retryAfter = getRetryAfterHeader();
            Collection<URI> rateLimits = getLinks("rate-limit");
            return new AcmeRateLimitExceededException(type, detail, retryAfter.orElse(null), rateLimits);
        }

        return new AcmeServerException(type, detail);
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
     * Resolves a relative link against the connection's last URI.
     *
     * @param link
     *            Link to resolve. Absolute links are just converted to an URI. May be
     *            {@code null}.
     * @return Absolute URI of the given link, or {@code null} if the link was
     *         {@code null}.
     */
    private URI resolveRelative(String link) {
        if (link == null) {
            return null;
        }

        assertConnectionIsOpen();
        try {
            return new URL(conn.getURL(), link).toURI();
        } catch (MalformedURLException | URISyntaxException ex) {
            throw new AcmeProtocolException("Cannot resolve relative link: " + link, ex);
        }
    }

}
