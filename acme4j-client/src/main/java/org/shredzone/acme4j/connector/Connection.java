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

import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;

/**
 * Connects to the ACME server and offers different methods for invoking the API.
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
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param session
     *            {@link Session} instance to be used for tracking
     */
    void sendRequest(URL url, Session session) throws AcmeException;

    /**
     * Sends a signed POST request. Ensures that the session has a KeyIdentifier set that
     * is used in the "kid" protected header.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims. Must not be {@code null}.
     * @param session
     *            {@link Session} instance to be used for signing and tracking
     */
    void sendSignedRequest(URL url, JSONBuilder claims, Session session) throws AcmeException;

    /**
     * Sends a signed POST request. If the session's KeyIdentifier is set, a "kid"
     * protected header is sent. If not, a "jwk" protected header is sent.
     *
     * @param url
     *            {@link URL} to send the request to.
     * @param claims
     *            {@link JSONBuilder} containing claims. Must not be {@code null}.
     * @param session
     *            {@link Session} instance to be used for signing and tracking
     */
    void sendJwkSignedRequest(URL url, JSONBuilder claims, Session session) throws AcmeException;

    /**
     * Checks if the HTTP response status is in the given list of acceptable HTTP states,
     * otherwise raises an {@link AcmeException} matching the error.
     *
     * @param httpStatus
     *            Acceptable HTTP states
     * @return Actual HTTP status that was accepted
     */
    int accept(int... httpStatus) throws AcmeException;

    /**
     * Reads a server response as JSON data.
     *
     * @return The JSON response
     */
    JSON readJsonResponse() throws AcmeException;

    /**
     * Reads a certificate and its issuers.
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
     * Updates a {@link Session} by evaluating the HTTP response header.
     *
     * @param session
     *            {@link Session} instance to be updated
     */
    void updateSession(Session session);

    /**
     * Gets a location from the {@code Location} header.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @return Location {@link URL}, or {@code null} if no Location header was set
     */
    URL getLocation();

    /**
     * Gets a relation link from the header. The result is expected to be an URL.
     * <p>
     * Relative links are resolved against the last request's URL. If there is more than
     * one relation, the first one is returned.
     *
     * @param relation
     *            Link relation
     * @return Link, or {@code null} if there was no such relation link
     */
    URL getLink(String relation);

    /**
     * Gets one or more relation links from the header.
     * <p>
     * Relative links are resolved against the last request's URL.
     *
     * @param relation
     *            Link relation
     * @return Collection of links, or {@code null} if there was no such relation link
     */
    Collection<URI> getLinks(String relation);

    /**
     * Closes the {@link Connection}, releasing all resources.
     */
    @Override
    void close();

}
