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

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Connects to the ACME server and offers different methods for invoking the API.
 * <p>
 * The actual way of communicating with the ACME server is intentionally left open.
 * Implementations could use other means than HTTP, or could mock the communication for
 * unit testing.
 */
public interface Connection extends AutoCloseable {

    /**
     * Resets the session nonce, by fetching a new one.
     *
     * @param session
     *            {@link Session} instance to fetch a nonce for
     */
    void resetNonce(Session session) throws AcmeException;

    /**
     * Sends a simple GET request.
     * <p>
     * If the response code was not HTTP status 200, an {@link AcmeException} matching
     * the error is raised.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param session
     *            {@link Session} instance to be used for tracking
     * @param ifModifiedSince
     *            {@link ZonedDateTime} to be sent as "If-Modified-Since" header, or
     *            {@code null} if this header is not to be used
     * @return HTTP status that was returned
     */
    int sendRequest(URL url, Session session, @Nullable ZonedDateTime ifModifiedSince)
            throws AcmeException;

    /**
     * Sends a signed POST-as-GET request for a certificate resource. Requires a
     * {@link Login} for the session and {@link KeyPair}. The {@link Login} account
     * location is sent in a "kid" protected header.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param login
     *            {@link Login} instance to be used for signing and tracking.
     * @return HTTP 200 class status that was returned
     */
    int sendCertificateRequest(URL url, Login login) throws AcmeException;

    /**
     * Sends a signed POST-as-GET request. Requires a {@link Login} for the session and
     * {@link KeyPair}. The {@link Login} account location is sent in a "kid" protected
     * header.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param login
     *            {@link Login} instance to be used for signing and tracking.
     * @return HTTP 200 class status that was returned
     */
    int sendSignedPostAsGetRequest(URL url, Login login) throws AcmeException;

    /**
     * Sends a signed POST request. Requires a {@link Login} for the session and
     * {@link KeyPair}. The {@link Login} account location is sent in a "kid" protected
     * header.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims.
     * @param login
     *            {@link Login} instance to be used for signing and tracking.
     * @return HTTP 200 class status that was returned
     */
    int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException;

    /**
     * Sends a signed POST request. Only requires a {@link Session}. The {@link KeyPair}
     * is sent in a "jwk" protected header field.
     * <p>
     * If the server does not return a 200 class status code, an {@link AcmeException} is
     * raised matching the error.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims.
     * @param session
     *            {@link Session} instance to be used for tracking.
     * @param keypair
     *            {@link KeyPair} to be used for signing.
     * @return HTTP 200 class status that was returned
     */
    int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair)
                throws AcmeException;

    /**
     * Reads a server response as JSON object.
     *
     * @return The JSON response.
     */
    JSON readJsonResponse() throws AcmeException;

    /**
     * Reads a certificate and its chain of issuers.
     *
     * @return List of X.509 certificate and chain that was read.
     */
    List<X509Certificate> readCertificates() throws AcmeException;

    /**
     * Throws an {@link AcmeRetryAfterException} if the last status was HTTP Accepted and
     * a Retry-After header was received.
     *
     * @param message
     *            Message to be sent along with the {@link AcmeRetryAfterException}
     */
    void handleRetryAfter(String message) throws AcmeException;

    /**
     * Gets the nonce from the nonce header.
     *
     * @return Base64 encoded nonce, or empty if no nonce header was set
     */
    Optional<String> getNonce();

    /**
     * Gets a location from the {@code Location} header.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @return Location {@link URL}, or empty if no Location header was set
     */
    Optional<URL> getLocation();

    /**
     * Returns the content of the last-modified header, if present.
     *
     * @return Date in the Last-Modified header, or empty if the server did not provide
     * this information.
     * @since 2.10
     */
    Optional<ZonedDateTime> getLastModified();

    /**
     * Returns the expiration date of the resource, if present.
     *
     * @return Expiration date, either from the Cache-Control or Expires header. If empty,
     * the server did not provide an expiration date, or forbid caching.
     * @since 2.10
     */
    Optional<ZonedDateTime> getExpiration();

    /**
     * Gets one or more relation links from the header. The result is expected to be a
     * URL.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @param relation
     *         Link relation
     * @return Collection of links. Empty if there was no such relation.
     */
    Collection<URL> getLinks(String relation);

    /**
     * Closes the {@link Connection}, releasing all resources.
     */
    @Override
    void close();

}
