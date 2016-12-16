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
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Dummy implementation of {@link Connection} that always fails. Single methods are
 * supposed to be overridden for testing.
 */
public class DummyConnection implements Connection {

    @Override
    public void sendRequest(URI uri, Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int accept(int... httpStatus) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, Object> readJsonResponse() {
        throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate readCertificate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateSession(Session session) {
        throw new UnsupportedOperationException();
    }

    @Override
    public URI getLocation() {
        throw new UnsupportedOperationException();
    }

    @Override
    public URI getLink(String relation) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<URI> getLinks(String relation) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date getRetryAfterHeader() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
        // closing is always safe
    }

}
