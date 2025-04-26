/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
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

import static java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;
import static java.util.function.Predicate.not;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.JoseUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link Connection}. It communicates with the ACME server via
 * HTTP, with a client that is provided by the given {@link HttpConnector}.
 */
public class DefaultConnection implements Connection {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConnection.class);

    private static final int HTTP_OK = 200;
    private static final int HTTP_CREATED = 201;
    private static final int HTTP_NO_CONTENT = 204;
    private static final int HTTP_NOT_MODIFIED = 304;

    private static final String ACCEPT_HEADER = "Accept";
    private static final String ACCEPT_CHARSET_HEADER = "Accept-Charset";
    private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";
    private static final String ACCEPT_ENCODING_HEADER = "Accept-Encoding";
    private static final String CACHE_CONTROL_HEADER = "Cache-Control";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String DATE_HEADER = "Date";
    private static final String EXPIRES_HEADER = "Expires";
    private static final String IF_MODIFIED_SINCE_HEADER = "If-Modified-Since";
    private static final String LAST_MODIFIED_HEADER = "Last-Modified";
    private static final String LINK_HEADER = "Link";
    private static final String LOCATION_HEADER = "Location";
    private static final String REPLAY_NONCE_HEADER = "Replay-Nonce";
    private static final String RETRY_AFTER_HEADER = "Retry-After";
    private static final String DEFAULT_CHARSET = "utf-8";
    private static final String MIME_JSON = "application/json";
    private static final String MIME_JSON_PROBLEM = "application/problem+json";
    private static final String MIME_CERTIFICATE_CHAIN = "application/pem-certificate-chain";

    private static final URI BAD_NONCE_ERROR = URI.create("urn:ietf:params:acme:error:badNonce");
    private static final int MAX_ATTEMPTS = 10;

    private static final Pattern NO_CACHE_PATTERN = Pattern.compile("(?:^|.*?,)\\s*no-(?:cache|store)\\s*(?:,.*|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern MAX_AGE_PATTERN = Pattern.compile("(?:^|.*?,)\\s*max-age=(\\d+)\\s*(?:,.*|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern DIGITS_ONLY_PATTERN = Pattern.compile("^\\d+$");

    protected final HttpConnector httpConnector;
    protected final HttpClient httpClient;
    protected @Nullable HttpResponse<InputStream> lastResponse;

    /**
     * Creates a new {@link DefaultConnection}.
     *
     * @param httpConnector
     *         {@link HttpConnector} to be used for HTTP connections
     */
    public DefaultConnection(HttpConnector httpConnector) {
        this.httpConnector = Objects.requireNonNull(httpConnector, "httpConnector");
        this.httpClient = httpConnector.createClientBuilder().build();
    }

    @Override
    public void resetNonce(Session session) throws AcmeException {
        assertConnectionIsClosed();

        try {
            session.setNonce(null);

            var newNonceUrl = session.resourceUrl(Resource.NEW_NONCE);

            LOG.debug("HEAD {}", newNonceUrl);

            sendRequest(session, newNonceUrl, b ->
                    b.method("HEAD", HttpRequest.BodyPublishers.noBody()));

            logHeaders();

            var rc = getResponse().statusCode();
            if (rc != HTTP_OK && rc != HTTP_NO_CONTENT) {
                throw new AcmeException("Server responded with HTTP " + rc + " while trying to retrieve a nonce");
            }

            session.setNonce(getNonce()
                    .orElseThrow(() -> new AcmeProtocolException("Server did not provide a nonce"))
            );
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } finally {
            close();
        }
    }

    @Override
    public int sendRequest(URL url, Session session, @Nullable ZonedDateTime ifModifiedSince)
            throws AcmeException {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(session, "session");
        assertConnectionIsClosed();

        LOG.debug("GET {}", url);

        try {
            sendRequest(session, url, builder -> {
                builder.GET();
                builder.header(ACCEPT_HEADER, MIME_JSON);
                if (ifModifiedSince != null) {
                    builder.header(IF_MODIFIED_SINCE_HEADER, ifModifiedSince.format(RFC_1123_DATE_TIME));
                }
            });

            logHeaders();

            getNonce().ifPresent(session::setNonce);

            var rc = getResponse().statusCode();
            if (rc != HTTP_OK && rc != HTTP_CREATED && (rc != HTTP_NOT_MODIFIED || ifModifiedSince == null)) {
                throwAcmeException();
            }
            return rc;
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public int sendCertificateRequest(URL url, Login login) throws AcmeException {
        return sendSignedRequest(url, null, login.getSession(), login.getKeyPair(),
                login.getAccountLocation(), MIME_CERTIFICATE_CHAIN);
    }

    @Override
    public int sendSignedPostAsGetRequest(URL url, Login login) throws AcmeException {
        return sendSignedRequest(url, null, login.getSession(), login.getKeyPair(),
                login.getAccountLocation(), MIME_JSON);
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
        return sendSignedRequest(url, claims, login.getSession(), login.getKeyPair(),
                login.getAccountLocation(), MIME_JSON);
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair)
            throws AcmeException {
        return sendSignedRequest(url, claims, session, keypair, null, MIME_JSON);
    }

    @Override
    public JSON readJsonResponse() throws AcmeException {
        expectContentType(Set.of(MIME_JSON, MIME_JSON_PROBLEM));

        try (var in = getResponseBody()) {
            var result = JSON.parse(in);
            LOG.debug("Result JSON: {}", result);
            return result;
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public List<X509Certificate> readCertificates() throws AcmeException {
        expectContentType(Set.of(MIME_CERTIFICATE_CHAIN));

        try (var in = new TrimmingInputStream(getResponseBody())) {
            var cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificates(in).stream()
                    .map(X509Certificate.class::cast)
                    .toList();
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        } catch (CertificateException ex) {
            throw new AcmeProtocolException("Failed to read certificate", ex);
        }
    }

    @Override
    public Optional<String> getNonce() {
        var nonceHeaderOpt = getResponse().headers()
                .firstValue(REPLAY_NONCE_HEADER)
                .map(String::trim)
                .filter(not(String::isEmpty));
        if (nonceHeaderOpt.isPresent()) {
            var nonceHeader = nonceHeaderOpt.get();

            if (!AcmeUtils.isValidBase64Url(nonceHeader)) {
                throw new AcmeProtocolException("Invalid replay nonce: " + nonceHeader);
            }

            LOG.debug("Replay Nonce: {}", nonceHeader);
        }
        return nonceHeaderOpt;
    }

    @Override
    public URL getLocation() {
        return getResponse().headers()
                .firstValue(LOCATION_HEADER)
                .map(l -> {
                    LOG.debug("Location: {}", l);
                    return l;
                })
                .map(this::resolveRelative)
                .orElseThrow(() -> new AcmeProtocolException("location header is missing"));
    }

    @Override
    public Optional<ZonedDateTime> getLastModified() {
        return getResponse().headers()
                .firstValue(LAST_MODIFIED_HEADER)
                .map(lm -> {
                    try {
                        return ZonedDateTime.parse(lm, RFC_1123_DATE_TIME);
                    } catch (DateTimeParseException ex) {
                        LOG.debug("Ignored invalid Last-Modified date: {}", lm, ex);
                        return null;
                    }
                });
    }

    @Override
    public Optional<ZonedDateTime> getExpiration() {
        var cacheControlHeader = getResponse().headers()
                .firstValue(CACHE_CONTROL_HEADER)
                .filter(not(h -> NO_CACHE_PATTERN.matcher(h).matches()))
                .map(MAX_AGE_PATTERN::matcher)
                .filter(Matcher::matches)
                .map(m -> Integer.parseInt(m.group(1)))
                .filter(maxAge -> maxAge != 0)
                .map(maxAge -> ZonedDateTime.now(ZoneId.of("UTC")).plusSeconds(maxAge));

        if (cacheControlHeader.isPresent()) {
            return cacheControlHeader;
        }

        return getResponse().headers()
                .firstValue(EXPIRES_HEADER)
                .flatMap(header -> {
                    try {
                        return Optional.of(ZonedDateTime.parse(header, RFC_1123_DATE_TIME));
                    } catch (DateTimeParseException ex) {
                        LOG.debug("Ignored invalid Expires date: {}", header, ex);
                        return Optional.empty();
                    }
                });
    }

    @Override
    public Collection<URL> getLinks(String relation) {
        return collectLinks(relation).stream()
                .map(this::resolveRelative)
                .toList();
    }

    @Override
    public void close() {
        lastResponse = null;
    }

    /**
     * Sends a HTTP request via http client. This is the central method to be used for
     * sending. It will create a {@link HttpRequest} by using the request builder,
     * configure commnon headers, and then send the request via {@link HttpClient}.
     *
     * @param session
     *         {@link Session} to be used for sending
     * @param url
     *         Target {@link URL}
     * @param body
     *         Callback that completes the {@link HttpRequest.Builder} with the request
     *         body (e.g. HTTP method, request body, more headers).
     */
    protected void sendRequest(Session session, URL url, Consumer<HttpRequest.Builder> body) throws IOException {
        try {
            var builder = httpConnector.createRequestBuilder(url)
                    .header(ACCEPT_CHARSET_HEADER, DEFAULT_CHARSET)
                    .header(ACCEPT_LANGUAGE_HEADER, session.getLanguageHeader());

            if (session.networkSettings().isCompressionEnabled()) {
                builder.header(ACCEPT_ENCODING_HEADER, "gzip");
            }

            body.accept(builder);

            lastResponse = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            throw new IOException("Request was interrupted", ex);
        }
    }

    /**
     * Sends a signed POST request.
     *
     * @param url
     *         {@link URL} to send the request to.
     * @param claims
     *         {@link JSONBuilder} containing claims. {@code null} for POST-as-GET
     *         request.
     * @param session
     *         {@link Session} instance to be used for signing and tracking
     * @param keypair
     *         {@link KeyPair} to be used for signing
     * @param accountLocation
     *         If set, the account location is set as "kid" header. If {@code null}, the
     *         public key is set as "jwk" header.
     * @param accept
     *         Accept header
     * @return HTTP 200 class status that was returned
     */
    protected int sendSignedRequest(URL url, @Nullable JSONBuilder claims, Session session,
                                    KeyPair keypair, @Nullable URL accountLocation, String accept) throws AcmeException {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(keypair, "keypair");
        Objects.requireNonNull(accept, "accept");
        assertConnectionIsClosed();

        var attempt = 1;
        while (true) {
            try {
                return performRequest(url, claims, session, keypair, accountLocation, accept);
            } catch (AcmeServerException ex) {
                if (!BAD_NONCE_ERROR.equals(ex.getType())) {
                    throw ex;
                }
                if (attempt == MAX_ATTEMPTS) {
                    throw ex;
                }
                LOG.info("Bad Replay Nonce, trying again (attempt {}/{})", attempt, MAX_ATTEMPTS);
                attempt++;
            }
        }
    }

    /**
     * Performs the POST request.
     *
     * @param url
     *         {@link URL} to send the request to.
     * @param claims
     *         {@link JSONBuilder} containing claims. {@code null} for POST-as-GET
     *         request.
     * @param session
     *         {@link Session} instance to be used for signing and tracking
     * @param keypair
     *         {@link KeyPair} to be used for signing
     * @param accountLocation
     *         If set, the account location is set as "kid" header. If {@code null}, the
     *         public key is set as "jwk" header.
     * @param accept
     *         Accept header
     * @return HTTP 200 class status that was returned
     */
    private int performRequest(URL url, @Nullable JSONBuilder claims, Session session,
                               KeyPair keypair, @Nullable URL accountLocation, String accept)
            throws AcmeException {
        try {
            if (session.getNonce() == null) {
                resetNonce(session);
            }

            var jose = JoseUtils.createJoseRequest(
                    url,
                    keypair,
                    claims,
                    session.getNonce(),
                    accountLocation != null ? accountLocation.toString() : null
            );

            var outputData = jose.toString();

            sendRequest(session, url, builder -> {
                builder.POST(HttpRequest.BodyPublishers.ofString(outputData));
                builder.header(ACCEPT_HEADER, accept);
                builder.header(CONTENT_TYPE_HEADER, "application/jose+json");
            });

            logHeaders();

            session.setNonce(getNonce().orElse(null));

            var rc = getResponse().statusCode();
            if (rc != HTTP_OK && rc != HTTP_CREATED) {
                throwAcmeException();
            }
            return rc;
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public Optional<Instant> getRetryAfter() {
        return getResponse().headers()
                .firstValue(RETRY_AFTER_HEADER)
                .map(this::parseRetryAfterHeader);
    }

    /**
     * Parses the content of a Retry-After header. The header can either contain a
     * relative or an absolute time.
     *
     * @param header
     *         Retry-After header
     * @return Instant given in the header
     * @throws AcmeProtocolException
     *         if the header content is invalid
     */
    private Instant parseRetryAfterHeader(String header) {
        // See RFC 2616 section 14.37
        try {
            // delta-seconds
            if (DIGITS_ONLY_PATTERN.matcher(header).matches()) {
                var delta = Integer.parseInt(header);
                var date = getResponse().headers().firstValue(DATE_HEADER)
                        .map(d -> ZonedDateTime.parse(d, RFC_1123_DATE_TIME).toInstant())
                        .orElseGet(Instant::now);
                return date.plusSeconds(delta);
            }

            // HTTP-date
            return ZonedDateTime.parse(header, RFC_1123_DATE_TIME).toInstant();
        } catch (RuntimeException ex) {
            throw new AcmeProtocolException("Bad retry-after header value: " + header, ex);
        }
    }

    /**
     * Provides an {@link InputStream} of the response body. If the stream is compressed,
     * it will also take care for decompression.
     */
    private InputStream getResponseBody() throws IOException {
        var stream = getResponse().body();
        if (stream == null) {
            throw new AcmeProtocolException("Unexpected empty response");
        }

        if (getResponse().headers().firstValue("Content-Encoding")
                .filter("gzip"::equalsIgnoreCase)
                .isPresent()) {
            stream = new GZIPInputStream(stream);
        }

        return stream;
    }

    /**
     * Throws an {@link AcmeException}. This method throws an exception that tries to
     * explain the error as precisely as possible.
     */
    private void throwAcmeException() throws AcmeException {
        try {
            if (getResponse().headers().firstValue(CONTENT_TYPE_HEADER)
                    .map(AcmeUtils::getContentType)
                    .filter(MIME_JSON_PROBLEM::equals)
                    .isEmpty()) {
                // Generic HTTP error
                throw new AcmeException("HTTP " + getResponse().statusCode());
            }

            var problem = new Problem(readJsonResponse(), getResponse().request().uri().toURL());

            var error = AcmeUtils.stripErrorPrefix(problem.getType().toString());

            if ("unauthorized".equals(error)) {
                throw new AcmeUnauthorizedException(problem);
            }

            if ("userActionRequired".equals(error)) {
                var tos = collectLinks("terms-of-service").stream()
                        .findFirst()
                        .map(this::resolveUri)
                        .orElse(null);
                throw new AcmeUserActionRequiredException(problem, tos);
            }

            if ("rateLimited".equals(error)) {
                var retryAfter = getRetryAfter();
                var rateLimits = getLinks("help");
                throw new AcmeRateLimitedException(problem, retryAfter.orElse(null), rateLimits);
            }

            throw new AcmeServerException(problem);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Checks if the returned content type is in the list of expected types.
     *
     * @param expectedTypes
     *         content types that are accepted
     * @throws AcmeProtocolException
     *         if the returned content type is different
     */
    private void expectContentType(Set<String> expectedTypes) {
        var contentType = getResponse().headers()
                .firstValue(CONTENT_TYPE_HEADER)
                .map(AcmeUtils::getContentType)
                .orElseThrow(() -> new AcmeProtocolException("No content type header found"));
        if (!expectedTypes.contains(contentType)) {
            throw new AcmeProtocolException("Unexpected content type: " + contentType);
        }
    }

    /**
     * Returns the response of the last request. If there is no connection currently
     * open, an exception is thrown instead.
     * <p>
     * Note that the response provides an {@link InputStream} that can be read only
     * once.
     */
    private HttpResponse<InputStream> getResponse() {
        if (lastResponse == null) {
            throw new IllegalStateException("Not connected.");
        }
        return lastResponse;
    }

    /**
     * Asserts that the connection is currently closed. Throws an exception if not.
     */
    private void assertConnectionIsClosed() {
        if (lastResponse != null) {
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

        getResponse().headers().map().forEach((key, headers) ->
                headers.forEach(value ->
                        LOG.debug("HEADER {}: {}", key, value)
                )
        );
    }

    /**
     * Collects links of the given relation.
     *
     * @param relation
     *         Link relation
     * @return Collection of links, unconverted
     */
    private Collection<String> collectLinks(String relation) {
        var p = Pattern.compile("<(.*?)>\\s*;\\s*rel=\"?" + Pattern.quote(relation) + "\"?");

        return getResponse().headers().allValues(LINK_HEADER)
                .stream()
                .map(p::matcher)
                .filter(Matcher::matches)
                .map(m -> m.group(1))
                .peek(location -> LOG.debug("Link: {} -> {}", relation, location))
                .toList();
    }

    /**
     * Resolves a relative link against the connection's last URL.
     *
     * @param link
     *         Link to resolve. Absolute links are just converted to an URL.
     * @return Absolute URL of the given link
     */
    private URL resolveRelative(String link) {
        try {
            return resolveUri(link).toURL();
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException("Cannot resolve relative link: " + link, ex);
        }
    }

    /**
     * Resolves a relative URI against the connection's last URL.
     *
     * @param uri
     *         URI to resolve
     * @return Absolute URI of the given link
     */
    private URI resolveUri(String uri) {
        return getResponse().request().uri().resolve(uri);
    }

}
