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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.GenericTokenChallenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
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
    /* package protected */ Date directoryCacheExpiry;

    /**
     * Creates a new {@link GenericAcmeClient}.
     *
     * @param provider
     *            {@link AcmeClientProvider} creating this client
     * @param directoryUri
     *            {@link URI} of the ACME server's directory service
     */
    public GenericAcmeClient(AcmeClientProvider provider, URI directoryUri) {
        if (provider == null) {
            throw new NullPointerException("provider must not be null");
        }

        this.provider = provider;
        this.directoryUri = directoryUri;
    }

    @Override
    protected Challenge createChallenge(Map<String, Object> data) {
        String type = (String) data.get("type");
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("type must not be empty or null");
        }

        Challenge challenge = provider.createChallenge(type);
        if (challenge == null) {
            if (data.containsKey("token")) {
                challenge = new GenericTokenChallenge();
            } else {
                challenge = new GenericChallenge();
            }
        }
        challenge.unmarshall(data);
        return challenge;
    }

    @Override
    protected Connection createConnection() {
        return provider.createConnection();
    }

    @Override
    protected URI resourceUri(Resource resource) throws AcmeException {
        if (resource == null) {
            throw new NullPointerException("resource must not be null");
        }

        Date now = new Date();

        if (directoryMap.isEmpty() || !directoryCacheExpiry.after(now)) {
            if (directoryUri == null) {
                throw new AcmeProtocolException("directoryUri was null on construction time");
            }

            try (Connection conn = createConnection()) {
                int rc = conn.sendRequest(directoryUri);
                if (rc != HttpURLConnection.HTTP_OK) {
                    conn.throwAcmeException();
                }

                // use nonce header if there is one, saves a HEAD request...
                conn.updateSession(getSession());

                Map<Resource, URI> newMap = conn.readDirectory();

                // only reached when readDirectory did not throw an exception
                directoryMap.clear();
                directoryMap.putAll(newMap);
                directoryCacheExpiry = new Date(now.getTime() + 60 * 60 * 1000L);
            } catch (IOException ex) {
                throw new AcmeNetworkException(ex);
            }
        }
        return directoryMap.get(resource);
    }

}
