/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A mock {@link Connection}. Its main purpose is to invoke the {@link
 * org.shredzone.acme4j.mock.controller.Controller} that is related to the request. No
 * actual HTTP request is sent.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockConnection implements Connection {
    private final Repository repository;
    private final NoncePool noncePool;

    private Result lastResult;
    private String lastNonce;

    /**
     * Creates a new connection.
     *
     * @param repository
     *         {@link Repository} to be used for resolving URLs
     * @param noncePool
     *         {@link NoncePool} to be used for nonces
     */
    public MockConnection(Repository repository, NoncePool noncePool) {
        this.repository = repository;
        this.noncePool = noncePool;
    }

    @Override
    public void resetNonce(Session session) {
        lastNonce = noncePool.generateNonce();
        session.setNonce(getNonce());
    }

    @Override
    public void sendRequest(URL url, Session session) throws AcmeException {
        assertConnectionIsClosed();
        resetNonce(session);
        lastResult = repository.getController(url)
                .orElseThrow(MockError::notFound)
                .doSimpleRequest(url);
    }

    @Override
    public int sendCertificateRequest(URL url, Login login) throws AcmeException {
        return sendSignedPostAsGetRequest(url, login);
    }

    @Override
    public int sendSignedPostAsGetRequest(URL url, Login login) throws AcmeException {
        assertConnectionIsClosed();
        validateAndUpdateNonce(url, login.getSession());
        lastResult = repository.getController(url)
                .orElseThrow(MockError::notFound)
                .doPostAsGetRequest(url, login.getKeyPair().getPublic());
        return HttpURLConnection.HTTP_OK;
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
        return sendSignedRequest(url, claims, login.getSession(), login.getKeyPair());
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair)
            throws AcmeException {
        assertConnectionIsClosed();
        validateAndUpdateNonce(url, session);
        lastResult = repository.getController(url)
                .orElseThrow(MockError::notFound)
                .doPostRequest(url, claims.toJSON(), keypair.getPublic());
        return HttpURLConnection.HTTP_OK;
    }

    @CheckForNull
    @Override
    public JSON readJsonResponse() {
        assertConnectionIsOpen();
        if (lastResult.getJSON() == null) {
            throw new IllegalStateException("Controller did not send a JSON response");
        }

        return lastResult.getJSON();
    }

    @Override
    public List<X509Certificate> readCertificates() {
        assertConnectionIsOpen();
        if (lastResult.getCertificate() == null) {
            throw new IllegalStateException("Controller did not send a certificate");
        }

        return lastResult.getCertificate();
    }

    @Override
    public void handleRetryAfter(String message) throws AcmeException {
        assertConnectionIsOpen();
        Instant retryAfter = lastResult.getRetryAfter();
        if (retryAfter != null) {
            throw new AcmeRetryAfterException(message, retryAfter);
        }
    }

    @CheckForNull
    @Override
    public String getNonce() {
        return lastNonce;
    }

    @CheckForNull
    @Override
    public URL getLocation() {
        assertConnectionIsOpen();
        return lastResult.getLocation();
    }

    @Override
    public Collection<URL> getLinks(String relation) {
        assertConnectionIsOpen();
        return Collections.emptyList();
    }

    @Override
    public void close() {
        lastResult = null;
    }

    /**
     * Asserts that the current connection is open.
     */
    private void assertConnectionIsOpen() {
        if (lastResult == null) {
            throw new IllegalStateException("No request was sent");
        }
    }

    /**
     * Asserts that the current connection is closed.
     */
    private void assertConnectionIsClosed() {
        if (lastResult != null) {
            throw new IllegalStateException("Connection is not closed");
        }
    }

    /**
     * Validates the nonce used in the {@link Session}. If it is valid, or if the session
     * did not contain a nonce yet, a new nonce is generated and set.
     *
     * @param requestUrl
     *         Request {@link URL}
     * @param session
     *         {@link Session} containing the nonce to be checked
     * @throws AcmeServerException
     *         if the {@link Session} contained an invalid nonce
     */
    private void validateAndUpdateNonce(URL requestUrl, Session session) throws AcmeServerException {
        if (session.getNonce() == null) {
            resetNonce(session);
        }

        String nonce = session.getNonce();
        if (nonce == null) {
            throw new IllegalStateException("Could not get a fresh nonce");
        }

        if (!noncePool.consumeNonce(nonce)) {
            throw MockError.badNonce(requestUrl);
        }

        lastNonce = noncePool.generateNonce();
        session.setNonce(getNonce());
    }

}
