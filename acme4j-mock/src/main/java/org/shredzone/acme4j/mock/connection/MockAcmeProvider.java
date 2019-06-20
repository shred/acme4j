/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import java.net.URI;
import java.net.URL;
import java.util.function.Function;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;

/**
 * A mock {@link org.shredzone.acme4j.provider.AcmeProvider} that immediately
 * connects to a {@link MockAcmeServer}.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockAcmeProvider extends AbstractAcmeProvider {
    public static final URI MOCK_URI = URI.create("acme://mock/");

    private final URL directoryUrl;
    private final Function<URI, Connection> connectionFactory;

    /**
     * Creates a new {@link MockAcmeProvider}.
     *
     * @param directoryUrl
     *         {@link URL} of the directory
     * @param connectionFactory
     *         A {@link Function} that creates a new {@link Connection} instance
     */
    public MockAcmeProvider(URL directoryUrl, Function<URI, Connection> connectionFactory) {
        this.directoryUrl = directoryUrl;
        this.connectionFactory = connectionFactory;
    }

    @Override
    public boolean accepts(URI serverUri) {
        return MOCK_URI.equals(serverUri);
    }

    @Override
    public URL resolve(URI serverUri) {
        return directoryUrl;
    }

    @Override
    public Connection connect(URI serverUri) {
        return connectionFactory.apply(serverUri);
    }

}
