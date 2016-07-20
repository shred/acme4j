/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.DummyConnection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Test implementation of {@link AcmeProvider}. It also implements a dummy implementation
 * of {@link Connection} that is always returned on {@link #connect()}.
 *
 * @author Richard "Shred" Körber
 */
public class TestableConnectionProvider extends DummyConnection implements AcmeProvider {
    private final Map<String, Challenge> challengeMap = new HashMap<>();
    private final ClaimBuilder directory = new ClaimBuilder();

    /**
     * Register a {@link Resource} mapping.
     *
     * @param r
     *            {@link Resource} to be mapped
     * @param u
     *            {@link URI} to be returned
     */
    public void putTestResource(Resource r, URI u) {
        directory.put(r.path(), u);
    }

    /**
     * Register a {@link Challenge}. For the sake of simplicity,
     * {@link #createChallenge(Session, String)} will always return the same
     * {@link Challenge} instance in this test suite.
     *
     * @param s
     *            Challenge type
     * @param c
     *            {@link Challenge} instance.
     */
    public void putTestChallenge(String s, Challenge c) {
        challengeMap.put(s, c);
    }

    /**
     * Creates a {@link Session} that uses this {@link AcmeProvider}.
     */
    public Session createSession() throws IOException {
        return TestUtils.session(this);
    }

    @Override
    public boolean accepts(URI serverUri) {
        throw new UnsupportedOperationException();
    }

    @Override
    public URI resolve(URI serverUri) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Connection connect() {
        return this;
    }

    @Override
    public Map<String, Object> directory(Session session, URI serverUri) throws AcmeException {
        Map<String, Object> result = directory.toMap();
        if (result.isEmpty()) {
            throw new UnsupportedOperationException();
        }
        return result;
    }

    @Override
    public Challenge createChallenge(Session session, String type) {
        if (challengeMap.isEmpty()) {
            throw new UnsupportedOperationException();
        }

        if (challengeMap.containsKey(type)) {
            return challengeMap.get(type);
        } else {
            return new Challenge(session);
        }
    }

}
