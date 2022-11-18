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
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.DummyConnection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Test implementation of {@link AcmeProvider}. It also implements a dummy implementation
 * of {@link Connection} that is always returned on {@link #connect(URI)}.
 */
public class TestableConnectionProvider extends DummyConnection implements AcmeProvider {
    private final Map<String, BiFunction<Login, JSON, Challenge>> creatorMap = new HashMap<>();
    private final Map<String, Challenge> createdMap = new HashMap<>();
    private final JSONBuilder directory = new JSONBuilder();
    private JSONBuilder metadata = null;

    /**
     * Register a {@link Resource} mapping.
     *
     * @param r
     *            {@link Resource} to be mapped
     * @param u
     *            {@link URL} to be returned
     */
    public void putTestResource(Resource r, URL u) {
        directory.put(r.path(), u);
    }

    /**
     * Add a property to the metadata registry.
     *
     * @param key
     *            Metadata key
     * @param value
     *            Metadata value
     */
    public void putMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = directory.object("meta");
        }
        metadata.put(key, value);
    }

    /**
     * Register a {@link Challenge}.
     *
     * @param type
     *            Challenge type to register.
     * @param creator
     *            Creator {@link BiFunction} that creates a matching {@link Challenge}
     */
    public void putTestChallenge(String type, BiFunction<Login, JSON, Challenge> creator) {
        creatorMap.put(type, creator);
    }

    /**
     * Returns the {@link Challenge} instance that has been created. Fails if no such
     * challenge was created.
     *
     * @param type Challenge type
     * @return Created {@link Challenge} instance
     */
    public Challenge getChallenge(String type) {
        if (!createdMap.containsKey(type)) {
            throw new IllegalArgumentException("No challenge of type " + type + " was created");
        }
        return createdMap.get(type);
    }

    /**
     * Creates a {@link Session} that uses this {@link AcmeProvider}.
     */
    public Session createSession() {
        return TestUtils.session(this);
    }

    /**
     * Creates a {@link Login} that uses this {@link AcmeProvider}.
     */
    public Login createLogin() throws IOException {
        var session = createSession();
        return session.login(new URL(TestUtils.ACCOUNT_URL), TestUtils.createKeyPair());
    }

    @Override
    public boolean accepts(URI serverUri) {
        throw new UnsupportedOperationException();
    }

    @Override
    public URL resolve(URI serverUri) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Connection connect(URI serverUri) {
        return this;
    }

    @Override
    public JSON directory(Session session, URI serverUri) {
        if (directory.toMap().isEmpty()) {
            throw new UnsupportedOperationException();
        }
        return directory.toJSON();
    }

    @Override
    public Challenge createChallenge(Login login, JSON data) {
        if (creatorMap.isEmpty()) {
            throw new UnsupportedOperationException();
        }

        Challenge created;

        var type = data.get("type").asString();
        if (creatorMap.containsKey(type)) {
            created = creatorMap.get(type).apply(login, data);
        } else {
            created = new Challenge(login, data);
        }

        createdMap.put(type, created);

        return created;
    }

}
