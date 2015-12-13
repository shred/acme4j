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
import java.util.EnumMap;
import java.util.Map;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeClientProvider;

/**
 * A generic implementation of {@link AcmeClient}. It uses an {@link AcmeClientProvider}
 * for managing individual server features.
 *
 * @author Richard "Shred" Körber
 */
public class GenericAcmeClient extends AbstractAcmeClient {

    private final AcmeClientProvider provider;
    private final URI directoryUri;
    private final Map<Resource, URI> directoryMap = new EnumMap<>(Resource.class);

    /**
     * Creates a new {@link GenericAcmeClient}.
     *
     * @param provider
     *            {@link AcmeClientProvider} creating this client
     * @param directoryUri
     *            {@link URI} of the ACME server's directory service
     */
    public GenericAcmeClient(AcmeClientProvider provider, URI directoryUri) {
        this.provider = provider;
        this.directoryUri = directoryUri;
    }

    @Override
    protected Challenge createChallenge(String type) {
        return provider.createChallenge(type);
    }

    @Override
    protected Connection connect() {
        return new Connection(provider);
    }

    @Override
    protected URI resourceUri(Resource resource) throws AcmeException {
        if (directoryMap.isEmpty()) {
            try (Connection conn = connect()) {
                conn.sendRequest(directoryUri);
                directoryMap.putAll(conn.readDirectory());
            }
        }
        return directoryMap.get(resource);
    }

}
