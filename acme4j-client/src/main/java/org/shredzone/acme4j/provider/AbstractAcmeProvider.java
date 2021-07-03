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
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
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

    private static final Map<String, ChallengeProvider> CHALLENGES = challengeMap();

    @Override
    public Connection connect(URI serverUri) {
        return new DefaultConnection(createHttpConnector());
    }

    @Override
    public JSON directory(Session session, URI serverUri) throws AcmeException {
        ZonedDateTime expires = session.getDirectoryExpires();
        if (expires != null && expires.isAfter(ZonedDateTime.now())) {
            // The cached directory is still valid
            return null;
        }

        try (Connection conn = connect(serverUri)) {
            ZonedDateTime lastModified = session.getDirectoryLastModified();
            int rc = conn.sendRequest(resolve(serverUri), session, lastModified);
            if (lastModified != null && rc == HttpURLConnection.HTTP_NOT_MODIFIED) {
                // The server has not been modified since
                return null;
            }

            // evaluate caching headers
            session.setDirectoryLastModified(conn.getLastModified().orElse(null));
            session.setDirectoryExpires(conn.getExpiration().orElse(null));

            // use nonce header if there is one, saves a HEAD request...
            String nonce = conn.getNonce();
            if (nonce != null) {
                session.setNonce(nonce);
            }

            return conn.readJsonResponse();
        }
    }

    private static Map<String, ChallengeProvider> challengeMap() {
        Map<String, ChallengeProvider> map = new HashMap<>();

        map.put(Dns01Challenge.TYPE, Dns01Challenge::new);
        map.put(Http01Challenge.TYPE, Http01Challenge::new);
        map.put(TlsAlpn01Challenge.TYPE, TlsAlpn01Challenge::new);

        for (ChallengeProvider provider : ServiceLoader.load(ChallengeProvider.class)) {
            ChallengeType typeAnno = provider.getClass().getAnnotation(ChallengeType.class);
            if (typeAnno == null) {
                throw new IllegalStateException("ChallengeProvider "
                        + provider.getClass().getName()
                        + " has no @ChallengeType annotation");
            }
            String type = typeAnno.value();
            if (type == null || type.trim().isEmpty()) {
                throw new IllegalStateException("ChallengeProvider "
                        + provider.getClass().getName()
                        + ": type must not be null or empty");
            }
            if (map.containsKey(type)) {
                throw new IllegalStateException("ChallengeProvider "
                        + provider.getClass().getName()
                        + ": there is already a provider for challenge type "
                        + type);
            }
            map.put(type, provider);
        }

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
    public Challenge createChallenge(Login login, JSON data) {
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(data, "data");

        String type = data.get("type").asString();

        ChallengeProvider constructor = CHALLENGES.get(type);
        if (constructor != null) {
            return constructor.create(login, data);
        }

        if (data.contains("token")) {
            return new TokenChallenge(login, data);
        } else {
            return new Challenge(login, data);
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
