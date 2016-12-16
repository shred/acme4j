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
package org.shredzone.acme4j.provider;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.OutOfBand01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.DefaultConnection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * Abstract implementation of {@link AcmeProvider}. It consists of a challenge
 * registry and a standard {@link HttpConnector}.
 * <p>
 * Implementing classes must implement at least {@link AcmeProvider#accepts(URI)}
 * and {@link AbstractAcmeProvider#resolve(URI)}.
 */
public abstract class AbstractAcmeProvider implements AcmeProvider {

    @Override
    public Connection connect() {
        return new DefaultConnection(createHttpConnector());
    }

    @Override
    public Map<String, Object> directory(Session session, URI serverUri) throws AcmeException {
        try (Connection conn = connect()) {
            conn.sendRequest(resolve(serverUri), session);
            conn.accept(HttpURLConnection.HTTP_OK);

            // use nonce header if there is one, saves a HEAD request...
            conn.updateSession(session);

            return conn.readJsonResponse();
        }
    }

    @Override
    @SuppressWarnings("deprecation") // must still provide deprecated challenges
    public Challenge createChallenge(Session session, String type) {
        if (session == null) {
            throw new NullPointerException("session must not be null");
        }

        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("no type given");
        }

        switch (type) {
            case Dns01Challenge.TYPE: return new Dns01Challenge(session);
            case org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE: return new org.shredzone.acme4j.challenge.TlsSni01Challenge(session);
            case TlsSni02Challenge.TYPE: return new TlsSni02Challenge(session);
            case Http01Challenge.TYPE: return new Http01Challenge(session);
            case OutOfBand01Challenge.TYPE: return new OutOfBand01Challenge(session);
            default: return null;
        }
    }

    /**
     * Creates a {@link HttpConnector}.
     * <p>
     * Subclasses may override this method to configure the {@link HttpConnector}.
     */
    protected HttpConnector createHttpConnector() {
        return new HttpConnector();
    }

}
