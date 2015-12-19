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
import java.security.cert.X509Certificate;
import java.util.Map;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Connects to the ACME server and offers different methods for invoking the API.
 *
 * @author Richard "Shred" Körber
 */
public interface Connection extends AutoCloseable {

    /**
     * Sends a simple GET request.
     *
     * @param uri
     *            {@link URI} to send the request to.
     * @return HTTP response code
     */
    int sendRequest(URI uri) throws AcmeException;

    /**
     * Sends a signed POST request.
     *
     * @param uri
     *            {@link URI} to send the request to.
     * @param claims
     *            {@link ClaimBuilder} containing claims. Must not be {@code null}.
     * @param session
     *            {@link Session} instance to be used for tracking
     * @param account
     *            {@link Account} to be used for signing the request
     * @return HTTP response code
     */
    int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException;

    /**
     * Reads a server response as JSON data.
     *
     * @return Map containing the parsed JSON data
     */
    Map<String, Object> readJsonResponse() throws AcmeException;

    /**
     * Reads a certificate.
     *
     * @return {@link X509Certificate} that was read.
     */
    X509Certificate readCertificate() throws AcmeException;

    /**
     * Reads a resource directory.
     *
     * @return Map of {@link Resource} and the respective {@link URI} to invoke
     */
    Map<Resource, URI> readDirectory() throws AcmeException;

    /**
     * Updates a {@link Session} by evaluating the HTTP response header.
     *
     * @param session
     *            {@link Session} instance to be updated
     */
    void updateSession(Session session) throws AcmeException;

    /**
     * Gets a location from the {@code Location} header.
     *
     * @return Location {@link URI}, or {@code null} if no Location header was set
     */
    URI getLocation() throws AcmeException;

    /**
     * Gets a link relation from the header.
     *
     * @param relation
     *            Link relation
     * @return Link, or {@code null} if there was no such link relation
     */
    URI getLink(String relation) throws AcmeException;

    /**
     * Handles a problem by throwing an exception. If a JSON problem was returned, an
     * {@link AcmeServerException} will be thrown. Otherwise a generic
     * {@link AcmeException} is thrown.
     */
    void throwAcmeException() throws AcmeException;

    /**
     * Closes the {@link Connection}, releasing all resources.
     */
    @Override
    void close();

}
