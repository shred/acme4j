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

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.challenge.TokenChallenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.DefaultConnection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Abstract implementation of {@link AcmeProvider}. It consists of a challenge
 * registry and a standard {@link HttpConnector}.
 * <p>
 * Implementing classes must implement at least {@link AcmeProvider#accepts(URI)}
 * and {@link AbstractAcmeProvider#resolve(URI)}.
 */
public abstract class AbstractAcmeProvider implements AcmeProvider {

    private static final Map<String, BiFunction<Session, JSON, Challenge>> CHALLENGES = challengeMap();

    @Override
    public Connection connect() {
        return new DefaultConnection(createHttpConnector());
    }

    @Override
    public JSON directory(Session session, URI serverUri) throws AcmeException {
        try (Connection conn = connect()) {
            conn.sendRequest(resolve(serverUri), session);

            // use nonce header if there is one, saves a HEAD request...
            conn.updateSession(session);

            return conn.readJsonResponse();
        }
    }

    private static Map<String, BiFunction<Session, JSON, Challenge>> challengeMap() {
        Map<String, BiFunction<Session, JSON, Challenge>> map = new HashMap<>();

        map.put(Dns01Challenge.TYPE, Dns01Challenge::new);
        map.put(TlsSni02Challenge.TYPE, TlsSni02Challenge::new);
        map.put(Http01Challenge.TYPE, Http01Challenge::new);

        return Collections.unmodifiableMap(map);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation handles the standard challenge types. For unknown types,
     * generic {@link Challenge} or {@link TokenChallenge} instances are created.
     * <p>
     * Custom provider implementations may override this method to provide challenges that
     * are unique to the provider.
     */
    @Override
    public Challenge createChallenge(Session session, JSON data) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(data, "data");

        String type = data.get("type").required().asString();

        BiFunction<Session, JSON, Challenge> constructor = CHALLENGES.get(type);
        if (constructor != null) {
            return constructor.apply(session, data);
        }

        if (data.contains("token")) {
            return new TokenChallenge(session, data);
        } else {
            return new Challenge(session, data);
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
