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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

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
    public void resetNonce(Session session) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void sendRequest(URL url, Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, int... httpStatus)
                throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedRequest(URL url, JSONBuilder claims, Session session, boolean enforceJwk, int... httpStatus)
                throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public JSON readJsonResponse() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<X509Certificate> readCertificates() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void handleRetryAfter(String message) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateSession(Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public URL getLocation() {
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
