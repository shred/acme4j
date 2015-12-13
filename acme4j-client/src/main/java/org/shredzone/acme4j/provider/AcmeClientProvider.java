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
import java.util.ServiceLoader;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.connector.Connection;

/**
 * An {@link AcmeClientProvider} creates {@link AcmeClient} instances to be used for
 * communicating with the ACME server. Implementations handle individual features of each
 * ACME server.
 * <p>
 * Provider implementations must be registered with Java's {@link ServiceLoader}.
 *
 * @author Richard "Shred" Körber
 */
public interface AcmeClientProvider {

    /**
     * Checks if this provider accepts the given server URI.
     *
     * @param serverUri
     *            Server URI to test
     * @return {@code true} if this provider accepts the server URI, {@code false}
     *         otherwise
     */
    boolean accepts(URI serverUri);

    /**
     * Connects to an {@link AcmeClient} for communication with the ACME server.
     *
     * @param serverUri
     *            Server URI to connect to
     * @return {@link AcmeClient} connected to the server
     */
    AcmeClient connect(URI serverUri);

    /**
     * Creates a {@link Challenge} instance that is able to respond to the challenge of
     * the given type.
     *
     * @param type
     *            Challenge type name
     * @return Matching {@link Challenge} instance
     * @throws ClassCastException
     *             if the expected {@link Challenge} type does not match the given type
     *             name.
     * @throws IllegalArgumentException
     *             if the given type name cannot be resolved to any {@link Challenge}
     *             class. However, for unknown challenge types, a {@link GenericChallenge}
     *             instance should be returned.
     */
    <T extends Challenge> T createChallenge(String type);

    /**
     * Creates a {@link Connection} for communication with the ACME server.
     *
     * @return {@link Connection} that was generated
     */
    Connection createConnection();

}
