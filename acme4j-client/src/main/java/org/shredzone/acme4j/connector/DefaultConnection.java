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

import static org.shredzone.acme4j.util.AcmeUtils.keyAlgorithm;

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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link Connection}.
 */
public class DefaultConnection implements Connection {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConnection.class);

    public static final String ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:";

    @Deprecated
    public static final String ACME_ERROR_PREFIX_DEPRECATED = "urn:acme:error:";

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("[0-9A-Za-z_-]+");

    protected final HttpConnector httpConnector;
    protected HttpURLConnection conn;

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
            conn.setRequestProperty("Accept-Charset", "utf-8");
            conn.setRequestProperty("Accept-Language", session.getLocale().toLanguageTag());
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
                conn.setRequestProperty("Accept-Language", session.getLocale().toLanguageTag());
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
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Accept-Charset", "utf-8");
            conn.setRequestProperty("Accept-Language", session.getLocale().toLanguageTag());
            conn.setRequestProperty("Content-Type", "application/jose+json");
            conn.setDoOutput(true);

            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toString());
            jws.getHeaders().setObjectHeaderValue("nonce", Base64Url.encode(session.getNonce()));
            jws.getHeaders().setObjectHeaderValue("url", uri);
            jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            jws.setAlgorithmHeaderValue(keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            byte[] outputData = jws.getCompactSerialization().getBytes("utf-8");

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
            for (int s : httpStatus) {
                if (s == rc) {
                    return rc;
                }
            }

            if (!"application/problem+json".equals(conn.getHeaderField("Content-Type"))) {
                throw new AcmeException("HTTP " + rc + ": " + conn.getResponseMessage());
            }

            JSON json = readJsonResponse();
            throw createAcmeException(rc, json);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public JSON readJsonResponse() throws AcmeException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField("Content-Type");
        if (!("application/json".equals(contentType)
                    || "application/problem+json".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        JSON result = null;

        String response = "";
        try {
            InputStream in =
                    conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream();
            if (in != null) {
                result = JSON.parse(in);
                LOG.debug("Result JSON: {}", response);
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }

        return result;
    }

    @Override
    public X509Certificate readCertificate() throws AcmeException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField("Content-Type");
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
                Date retryAfter = getRetryAfterHeader();
                if (retryAfter != null) {
                    throw new AcmeRetryAfterException(message, retryAfter);
                }
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void updateSession(Session session) {
        assertConnectionIsOpen();

        String nonceHeader = conn.getHeaderField("Replay-Nonce");
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

        String location = conn.getHeaderField("Location");
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

        List<String> links = conn.getHeaderFields().get("Link");
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
    private Date getRetryAfterHeader() {
        // See RFC 2616 section 14.37
        String header = conn.getHeaderField("Retry-After");
        if (header == null) {
            return null;
        }

        try {
            // delta-seconds
            if (header.matches("^\\d+$")) {
                int delta = Integer.parseInt(header);
                long date = conn.getHeaderFieldDate("Date", System.currentTimeMillis());
                return new Date(date + delta * 1000L);
            }

            // HTTP-date
            long date = conn.getHeaderFieldDate("Retry-After", 0L);
            return date != 0 ? new Date(date) : null;
        } catch (Exception ex) {
            throw new AcmeProtocolException("Bad retry-after header value: " + header, ex);
        }
    }

    /**
     * Handles a problem by throwing an exception. If a JSON problem was returned, an
     * {@link AcmeServerException} will be thrown. Otherwise a generic
     * {@link AcmeException} is thrown.
     */
    private AcmeException createAcmeException(int rc, JSON json) {
        String type = json.get("type").asString();
        String detail = json.get("detail").asString();

        if (detail == null) {
            detail = "general problem";
        }

        if (rc == HttpURLConnection.HTTP_CONFLICT) {
            return new AcmeConflictException(detail, getLocation());
        }

        if (type == null) {
            return new AcmeException(detail);
        }

        switch (type) {
            case ACME_ERROR_PREFIX + "unauthorized":
            case ACME_ERROR_PREFIX_DEPRECATED + "unauthorized":
                return new AcmeUnauthorizedException(type, detail);

            case ACME_ERROR_PREFIX + "agreementRequired":
            case ACME_ERROR_PREFIX_DEPRECATED + "agreementRequired":
                String instance = json.get("instance").asString();
                return new AcmeAgreementRequiredException(
                            type, detail, getLink("terms-of-service"),
                            instance != null ? resolveRelative(instance) : null);

            case ACME_ERROR_PREFIX + "rateLimited":
            case ACME_ERROR_PREFIX_DEPRECATED + "rateLimited":
                return new AcmeRateLimitExceededException(
                            type, detail, getRetryAfterHeader(), getLinks("rate-limit"));

            default:
                return new AcmeServerException(type, detail);
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

        for (Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
            for (String value : entry.getValue()) {
                LOG.debug("HEADER {}: {}", entry.getKey(), value);
            }
        }
    }

    /**
     * Resolves a relative link against the connection's last URI.
     *
     * @param link
     *            Link to resolve. Absolute links are just converted to an URI.
     * @return Absolute URI of the given link.
     */
    private URI resolveRelative(String link) {
        assertConnectionIsOpen();
        try {
            return new URL(conn.getURL(), link).toURI();
        } catch (MalformedURLException | URISyntaxException ex) {
            throw new AcmeProtocolException("Cannot resolve relative link: " + link, ex);
        }
    }

}
