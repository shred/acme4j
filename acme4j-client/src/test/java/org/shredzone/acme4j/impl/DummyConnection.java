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
package org.shredzone.acme4j.impl;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Dummy implementation of {@link Connection} that always fails. Single methods are
 * supposed to be overridden for testing.
 *
 * @author Richard "Shred" Körber
 */
public class DummyConnection implements Connection {

    @Override
    public void startSession(URI uri, Session session) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendRequest(URI uri) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, Object> readJsonResponse() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate readCertificate() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<Resource, URI> readDirectory() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public URI getLocation() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public URI getLink(String relation) throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void throwAcmeException() throws AcmeException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
        // closing is always safe
    }

}
