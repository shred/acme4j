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
import java.net.URL;
import java.net.http.HttpClient;
import java.util.Optional;
import java.util.ServiceLoader;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * An {@link AcmeProvider} provides methods to be used for communicating with the ACME
 * server. Implementations handle individual features of each ACME server.
 * <p>
 * Provider implementations must be registered with Java's {@link ServiceLoader}.
 */
public interface AcmeProvider {

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
     * Resolves the server URI and returns the matching directory URL.
     *
     * @param serverUri
     *            Server {@link URI}
     * @return Resolved directory {@link URL}
     * @throws IllegalArgumentException
     *             if the server {@link URI} is not accepted
     */
    URL resolve(URI serverUri);

    /**
     * Creates an {@link HttpClient} instance configured with the given network settings.
     * <p>
     * The default implementation creates a standard HttpClient with the network settings.
     * Subclasses can override this method to create a customized HttpClient, for example
     * to configure SSL context or other provider-specific requirements.
     *
     * @param networkSettings The network settings to use
     * @return {@link HttpClient} instance
     * @since 4.0.0
     */
    default HttpClient createHttpClient(NetworkSettings networkSettings) {
        var builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(networkSettings.getTimeout())
                .proxy(networkSettings.getProxySelector());

        if (networkSettings.getAuthenticator() != null) {
            builder.authenticator(networkSettings.getAuthenticator());
        }

        return builder.build();
    }

    /**
     * Creates a {@link Connection} for communication with the ACME server.
     *
     * @param serverUri
     *         Server {@link URI}
     * @param networkSettings
     *         {@link NetworkSettings} to be used for the connection
     * @param httpClient
     *         {@link HttpClient} to be used for HTTP requests
     * @return {@link Connection} that was generated
     * @since 4.0.0
     */
    Connection connect(URI serverUri, NetworkSettings networkSettings, HttpClient httpClient);

    /**
     * Returns the provider's directory. The structure must contain resource URLs, and may
     * optionally contain metadata.
     * <p>
     * The default implementation resolves the server URI and fetches the directory via
     * HTTP request. Subclasses may override this method, e.g. if the directory is static.
     *
     * @param session
     *            {@link Session} to be used
     * @param serverUri
     *            Server {@link URI}
     * @return Directory data, as JSON object, or {@code null} if the directory has not
     * been changed since the last request.
     */
    @Nullable
    JSON directory(Session session, URI serverUri) throws AcmeException;

    /**
     * Creates a {@link Challenge} instance for the given challenge data.
     *
     * @param login
     *            {@link Login} to bind the challenge to
     * @param data
     *            Challenge {@link JSON} data
     * @return {@link Challenge} instance, or {@code null} if this provider is unable to
     *         generate a matching {@link Challenge} instance.
     */
    @Nullable
    Challenge createChallenge(Login login, JSON data);

    /**
     * Returns a proposal for the EAB MAC algorithm to be used. Only set if the CA
     * requires External Account Binding and the MAC algorithm cannot be correctly derived
     * from the MAC key. Empty otherwise.
     *
     * @return Proposed MAC algorithm to be used for EAB, or empty for the default
     * behavior.
     * @since 3.5.0
     */
    default Optional<String> getProposedEabMacAlgorithm() {
        return Optional.empty();
    }

}
