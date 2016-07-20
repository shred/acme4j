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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitExceededException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link Connection}.
 *
 * @author Richard "Shred" Körber
 */
public class DefaultConnection implements Connection {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConnection.class);

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("[0-9A-Za-z_-]+");

    protected final HttpConnector httpConnector;
    protected HttpURLConnection conn;

    public DefaultConnection(HttpConnector httpConnector) {
        if (httpConnector == null) {
            throw new NullPointerException("httpConnector must not be null");
        }

        this.httpConnector = httpConnector;
    }

    @Override
    public int sendRequest(URI uri) throws IOException {
        if (uri == null) {
            throw new NullPointerException("uri must not be null");
        }
        assertConnectionIsClosed();

        LOG.debug("GET {}", uri);

        conn = httpConnector.openConnection(uri);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept-Charset", "utf-8");
        conn.setDoOutput(false);

        conn.connect();

        logHeaders();

        return conn.getResponseCode();
    }

    @Override
    public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) throws IOException {
        if (uri == null) {
            throw new NullPointerException("uri must not be null");
        }
        if (claims == null) {
            throw new NullPointerException("claims must not be null");
        }
        if (session == null) {
            throw new NullPointerException("session must not be null");
        }
        assertConnectionIsClosed();

        try {
            KeyPair keypair = session.getKeyPair();

            if (session.getNonce() == null) {
                LOG.debug("Getting initial nonce, HEAD {}", uri);
                conn = httpConnector.openConnection(uri);
                conn.setRequestMethod("HEAD");
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
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toString());
            jws.getHeaders().setObjectHeaderValue("nonce", Base64Url.encode(session.getNonce()));
            jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            jws.setAlgorithmHeaderValue(SignatureUtils.keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            byte[] outputData = jws.getCompactSerialization().getBytes("utf-8");

            conn.setFixedLengthStreamingMode(outputData.length);
            conn.connect();

            try (OutputStream out = conn.getOutputStream()) {
                out.write(outputData);
            }

            logHeaders();

            updateSession(session);

            return conn.getResponseCode();
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to generate a JSON request", ex);
        }
    }

    @Override
    public Map<String, Object> readJsonResponse() throws IOException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField("Content-Type");
        if (!("application/json".equals(contentType)
                    || "application/problem+json".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        Map<String, Object> result = null;

        String response = "";
        try {
            InputStream in = (conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream());
            if (in != null) {
                response = readStream(in);
                result = JsonUtil.parseJson(response);
                LOG.debug("Result JSON: {}", response);
            }
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to parse response: " + response, ex);
        }

        return result;
    }

    private String readStream(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, "utf-8"))) {
            String line = reader.readLine();

            while (line != null) {
                sb.append(line.trim());
                line = reader.readLine();
            }
        }

        return sb.toString();
    }

    @Override
    public X509Certificate readCertificate() throws IOException {
        assertConnectionIsOpen();

        String contentType = conn.getHeaderField("Content-Type");
        if (!("application/pkix-cert".equals(contentType))) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }

        try (InputStream in = conn.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (CertificateException ex) {
            throw new AcmeProtocolException("Failed to read certificate", ex);
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
        assertConnectionIsOpen();

        List<String> links = conn.getHeaderFields().get("Link");
        if (links != null) {
            Pattern p = Pattern.compile("<(.*?)>\\s*;\\s*rel=\"?"+ Pattern.quote(relation) + "\"?");
            for (String link : links) {
                Matcher m = p.matcher(link);
                if (m.matches()) {
                    String location = m.group(1);
                    LOG.debug("Link: {} -> {}", relation, location);
                    return resolveRelative(location);
                }
            }
        }

        return null;
    }

    @Override
    public Date getRetryAfterHeader() {
        assertConnectionIsOpen();

        // See RFC 2616 section 14.37
        String header = conn.getHeaderField("Retry-After");

        try {
            // delta-seconds
            if (header.matches("^\\d+$")) {
                int delta = Integer.parseInt(header);
                long date = conn.getHeaderFieldDate("Date", System.currentTimeMillis());
                return new Date(date + delta * 1000L);
            }

            // HTTP-date
            long date = conn.getHeaderFieldDate("Retry-After", 0L);
            return (date != 0 ? new Date(date) : null);
        } catch (Exception ex) {
            throw new AcmeProtocolException("Bad retry-after header value: " + header, ex);
        }
    }

    @Override
    public void throwAcmeException() throws AcmeException, IOException {
        assertConnectionIsOpen();

        if ("application/problem+json".equals(conn.getHeaderField("Content-Type"))) {
            Map<String, Object> map = readJsonResponse();
            String type = (String) map.get("type");
            String detail = (String) map.get("detail");

            if (detail == null) {
                detail = "general problem";
            }

            if (conn.getResponseCode() == HttpURLConnection.HTTP_CONFLICT) {
                throw new AcmeConflictException(detail, getLocation());
            }

            if (type == null) {
                throw new AcmeException(detail);
            }

            switch (type) {
                case "urn:acme:error:unauthorized":
                case "urn:ietf:params:acme:error:unauthorized":
                    throw new AcmeUnauthorizedException(type, detail);

                case "urn:acme:error:rateLimited":
                case "urn:ietf:params:acme:error:rateLimited":
                    throw new AcmeRateLimitExceededException(type, detail, getRetryAfterHeader());

                default:
                    throw new AcmeServerException(type, detail);
            }
        } else {
            throw new AcmeException("HTTP " + conn.getResponseCode() + ": "
                + conn.getResponseMessage());
        }
    }

    @Override
    public void close() {
        conn = null;
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
        if (LOG.isDebugEnabled()) {
            Map<String, List<String>> headers = conn.getHeaderFields();
            for (String key : headers.keySet()) {
                for (String value : headers.get(key)) {
                    LOG.debug("HEADER {}: {}", key, value);
                }
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
