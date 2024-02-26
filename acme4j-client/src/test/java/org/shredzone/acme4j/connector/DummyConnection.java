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
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Dummy implementation of {@link Connection} that always fails. Single methods are
 * supposed to be overridden for testing.
 */
public class DummyConnection implements Connection {

    @Override
    public void resetNonce(Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendRequest(URL url, Session session, ZonedDateTime ifModifiedSince) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendCertificateRequest(URL url, Login login) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedPostAsGetRequest(URL url, Login login) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Login login)
                throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
        throw new UnsupportedOperationException();
    }

    @Override
    public JSON readJsonResponse() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<X509Certificate> readCertificates() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<Instant> getRetryAfter() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<String> getNonce() {
        throw new UnsupportedOperationException();
    }

    @Override
    public URL getLocation() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<ZonedDateTime> getLastModified() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<ZonedDateTime> getExpiration() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<URL> getLinks(String relation) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
        // closing is always safe
    }

}
