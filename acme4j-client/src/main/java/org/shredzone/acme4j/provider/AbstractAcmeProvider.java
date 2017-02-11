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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

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
import org.shredzone.acme4j.util.JSON;

/**
 * Abstract implementation of {@link AcmeProvider}. It consists of a challenge
 * registry and a standard {@link HttpConnector}.
 * <p>
 * Implementing classes must implement at least {@link AcmeProvider#accepts(URI)}
 * and {@link AbstractAcmeProvider#resolve(URI)}.
 */
public abstract class AbstractAcmeProvider implements AcmeProvider {

    private static final Map<String, Function<Session, Challenge>> CHALLENGES = challengeMap();

    @Override
    public Connection connect() {
        return new DefaultConnection(createHttpConnector());
    }

    @Override
    public JSON directory(Session session, URI serverUri) throws AcmeException {
        try (Connection conn = connect()) {
            conn.sendRequest(resolve(serverUri), session);
            conn.accept(HttpURLConnection.HTTP_OK);

            // use nonce header if there is one, saves a HEAD request...
            conn.updateSession(session);

            return conn.readJsonResponse();
        }
    }

    private static Map<String, Function<Session, Challenge>> challengeMap() {
        Map<String, Function<Session, Challenge>> map = new HashMap<>();

        map.put(Dns01Challenge.TYPE, Dns01Challenge::new);
        map.put(TlsSni02Challenge.TYPE, TlsSni02Challenge::new);
        map.put(Http01Challenge.TYPE, Http01Challenge::new);
        map.put(OutOfBand01Challenge.TYPE, OutOfBand01Challenge::new);

        return Collections.unmodifiableMap(map);
    }

    @Override
    public Challenge createChallenge(Session session, String type) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(type, "type");

        Function<Session, Challenge> constructor = CHALLENGES.get(type);
        if (constructor == null) {
            return null;
        }

        return constructor.apply(session);
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
