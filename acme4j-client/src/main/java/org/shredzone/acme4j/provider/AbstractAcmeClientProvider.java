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

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.ProofOfPossession01Challenge;
import org.shredzone.acme4j.challenge.TlsSni01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.impl.DefaultConnection;
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
@SuppressWarnings("deprecation") // must also provide deprecated challenges
public abstract class AbstractAcmeClientProvider implements AcmeClientProvider {

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
        if (serverUri == null) {
            throw new NullPointerException("serverUri must not be null");
        }

        if (!accepts(serverUri)) {
            throw new IllegalArgumentException("This provider does not accept " + serverUri);
        }

        return createAcmeClient(resolve(serverUri));
    }

    @Override
    public Challenge createChallenge(String type) {
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("no type given");
        }

        switch (type) {
            case Dns01Challenge.TYPE: return new Dns01Challenge();
            case TlsSni01Challenge.TYPE: return new TlsSni01Challenge();
            case TlsSni02Challenge.TYPE: return new TlsSni02Challenge();
            case ProofOfPossession01Challenge.TYPE: return new ProofOfPossession01Challenge();
            case Http01Challenge.TYPE: return new Http01Challenge();
            default: return null;
        }
    }

    @Override
    public Connection createConnection() {
        return new DefaultConnection(createHttpConnector());
    }

    /**
     * Creates a {@link HttpConnector}. Subclasses may override this method to
     * configure the {@link HttpConnector}.
     */
    protected HttpConnector createHttpConnector() {
        return new HttpConnector();
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
