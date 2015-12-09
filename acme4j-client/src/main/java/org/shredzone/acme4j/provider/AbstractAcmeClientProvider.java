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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.DnsChallenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.challenge.ProofOfPossessionChallenge;
import org.shredzone.acme4j.challenge.TlsSniChallenge;

/**
 * Abstract implementation of {@link AcmeClientProvider}. It consists of a challenge
 * registry and a standard {@link #openConnection(URI)} implementation.
 *
 * @author Richard "Shred" Körber
 */
public abstract class AbstractAcmeClientProvider implements AcmeClientProvider {

    private static final int TIMEOUT = 10000;

    private final Map<String, Class<? extends Challenge>> challenges = new HashMap<>();

    public AbstractAcmeClientProvider() {
        registerBaseChallenges();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends Challenge> T createChallenge(String type) {
        Class<? extends Challenge> clazz = challenges.get(type);
        if (clazz == null) {
            return (T) new GenericChallenge();
        }

        try {
            return (T) clazz.newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalArgumentException("Could not create Challenge for type "
                + type, ex);
        }
    }

    @Override
    public HttpURLConnection openConnection(URI uri) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
        conn.setUseCaches(false);
        conn.setRequestProperty("User-Agent", "acme4j");
        return conn;
    }

    /**
     * Registers an individual {@link Challenge}. If a challenge of that type is already
     * registered, it will be replaced.
     *
     * @param type
     *            Challenge type string
     * @param clazz
     *            Class implementing the {@link Challenge}. It must have a default
     *            constructor.
     */
    protected void registerChallenge(String type, Class<? extends Challenge> clazz) {
        challenges.put(type, clazz);
    }

    /**
     * Registers all standard challenges as specified in the ACME specifications.
     * <p>
     * Subclasses may override this method in order to add further challenges. It is
     * invoked on construction time.
     */
    protected void registerBaseChallenges() {
        registerChallenge(DnsChallenge.TYPE, DnsChallenge.class);
        registerChallenge(TlsSniChallenge.TYPE, TlsSniChallenge.class);
        registerChallenge(ProofOfPossessionChallenge.TYPE, ProofOfPossessionChallenge.class);
        registerChallenge(HttpChallenge.TYPE, HttpChallenge.class);
    }

}
