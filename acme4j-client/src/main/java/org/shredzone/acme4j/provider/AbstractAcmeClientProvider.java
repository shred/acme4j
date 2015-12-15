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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.DnsChallenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.challenge.ProofOfPossessionChallenge;
import org.shredzone.acme4j.challenge.TlsSniChallenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.impl.GenericAcmeClient;

/**
 * Abstract implementation of {@link AcmeClientProvider}. It consists of a challenge
 * registry and a standard {@link HttpConnector}.
 * <p>
 * Implementing classes must implement at least {@link AcmeClientProvider#accepts(URI)}
 * and {@link AbstractAcmeClientProvider#resolve(URI)}.
 *
 * @author Richard "Shred" Körber
 */
public abstract class AbstractAcmeClientProvider implements AcmeClientProvider {

    private final Map<String, Class<? extends Challenge>> challenges = new HashMap<>();

    public AbstractAcmeClientProvider() {
        registerBaseChallenges();
    }

    /**
     * Resolves the server URI and returns the matching directory URI.
     *
     * @param serverUri
     *            Server {@link URI}
     * @return Resolved directory {@link URI}
     * @throws IllegalArgumentException
     *             if the server {@link URI} is not accepted
     */
    protected abstract URI resolve(URI serverUri);

    @Override
    public AcmeClient connect(URI serverUri) {
        if (!accepts(serverUri)) {
            throw new IllegalArgumentException("This provider does not accept " + serverUri);
        }

        return createAcmeClient(resolve(serverUri));
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
    public Connection createConnection() {
        return new Connection(createHttpConnector());
    }

    /**
     * Creates a {@link HttpConnector}. Subclasses may override this method to
     * configure the {@link HttpConnector}.
     */
    protected HttpConnector createHttpConnector() {
        return new HttpConnector();
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
        if (type == null) {
            throw new NullPointerException("type must not be null");
        }
        if (clazz == null) {
            throw new NullPointerException("Challenge class must not be null");
        }
        if (type.trim().isEmpty()) {
            throw new IllegalArgumentException("type must not be empty");
        }

        challenges.put(type, clazz);
    }

    /**
     * Returns all registered challenge types.
     */
    protected Collection<String> getRegisteredChallengeTypes() {
        return Collections.unmodifiableCollection(challenges.keySet());
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

    /**
     * Creates an {@link AcmeClient} for the given directory URI.
     *
     * @param directoryUri
     *            Directory {@link URI}
     * @return {@link AcmeClient}
     */
    protected AcmeClient createAcmeClient(URI directoryUri) {
        return new GenericAcmeClient(this, directoryUri);
    }

}
