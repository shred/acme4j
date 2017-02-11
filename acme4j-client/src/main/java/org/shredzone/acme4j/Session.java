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
package org.shredzone.acme4j;

import java.net.URI;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.TokenChallenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.util.JSON;

/**
 * A session stores the ACME server URI and the account's key pair. It also tracks
 * communication parameters.
 * <p>
 * Note that {@link Session} objects are not serializable, as they contain a keypair and
 * volatile data.
 */
public class Session {
    private final Map<Resource, URI> resourceMap = new EnumMap<>(Resource.class);
    private final URI serverUri;

    private KeyPair keyPair;
    private AcmeProvider provider;
    private byte[] nonce;
    private JSON directoryJson;
    private Metadata metadata;
    private Locale locale = Locale.getDefault();
    protected Instant directoryCacheExpiry;

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *            URI string of the ACME server
     * @param keyPair
     *            {@link KeyPair} of the ACME account
     */
    public Session(String serverUri, KeyPair keyPair) {
        this(URI.create(serverUri), keyPair);
    }

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *            {@link URI} of the ACME server
     * @param keyPair
     *            {@link KeyPair} of the ACME account
     */
    public Session(URI serverUri, KeyPair keyPair) {
        this.serverUri = Objects.requireNonNull(serverUri, "serverUri");
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
    }

    /**
     * Gets the ACME server {@link URI} of this session.
     */
    public URI getServerUri() {
        return serverUri;
    }

    /**
     * Gets the {@link KeyPair} of the ACME account.
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * Sets a different {@link KeyPair}.
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Gets the last nonce, or {@code null} if the session is new.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce received by the server.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Gets the current locale of this session.
     */
    public Locale getLocale() {
        return locale;
    }

    /**
     * Sets the locale used in this session. The locale is passed to the server as
     * Accept-Language header. The server <em>may</em> respond with localized messages.
     */
    public void setLocale(Locale locale) {
        this.locale = locale;
    }

    /**
     * Returns the {@link AcmeProvider} that is used for this session.
     * <p>
     * The {@link AcmeProvider} instance is lazily created and cached.
     *
     * @return {@link AcmeProvider}
     */
    public AcmeProvider provider() {
        synchronized (this) {
            if (provider == null) {
                List<AcmeProvider> candidates = new ArrayList<>();
                for (AcmeProvider acp : ServiceLoader.load(AcmeProvider.class)) {
                    if (acp.accepts(serverUri)) {
                        candidates.add(acp);
                    }
                }

                if (candidates.isEmpty()) {
                    throw new IllegalArgumentException("No ACME provider found for " + serverUri);
                } else if (candidates.size() > 1) {
                    throw new IllegalStateException("There are " + candidates.size() + " "
                        + AcmeProvider.class.getSimpleName() + " accepting " + serverUri
                        + ". Please check your classpath.");
                } else {
                    provider = candidates.get(0);
                }
            }
        }
        return provider;
    }

    /**
     * Creates a {@link Challenge} instance for the given challenge data.
     *
     * @param data
     *            Challenge JSON data
     * @return {@link Challenge} instance
     */
    public Challenge createChallenge(JSON data) {
        Objects.requireNonNull(data, "data");

        String type = data.get("type").required().asString();

        Challenge challenge = provider().createChallenge(this, type);
        if (challenge == null) {
            if (data.contains("token")) {
                challenge = new TokenChallenge(this);
            } else {
                challenge = new Challenge(this);
            }
        }
        challenge.unmarshall(data);
        return challenge;
    }

    /**
     * Gets the {@link URI} of the given {@link Resource}. This may involve connecting to
     * the server and getting a directory. The result is cached.
     *
     * @param resource
     *            {@link Resource} to get the {@link URI} of
     * @return {@link URI}, or {@code null} if the server does not offer that resource
     */
    public URI resourceUri(Resource resource) throws AcmeException {
        readDirectory();
        return resourceMap.get(Objects.requireNonNull(resource, "resource"));
    }

    /**
     * Gets the metadata of the provider's directory. This may involve connecting to the
     * server and getting a directory. The result is cached.
     *
     * @return {@link Metadata}. May contain no data, but is never {@code null}.
     */
    public Metadata getMetadata() throws AcmeException {
        readDirectory();
        return metadata;
    }

    /**
     * Reads the provider's directory, then rebuild the resource map. The response is
     * cached.
     */
    private void readDirectory() throws AcmeException {
        synchronized (this) {
            Instant now = Instant.now();
            if (directoryJson == null || !directoryCacheExpiry.isAfter(now)) {
                directoryJson = provider().directory(this, getServerUri());
                directoryCacheExpiry = now.plus(Duration.ofHours(1));

                JSON meta = directoryJson.get("meta").asObject();
                if (meta != null) {
                    metadata = new Metadata(meta);
                } else {
                    metadata = new Metadata(JSON.empty());
                }

                resourceMap.clear();
                for (Resource res : Resource.values()) {
                    URI uri = directoryJson.get(res.path()).asURI();
                    if (uri != null) {
                        resourceMap.put(res, uri);
                    }
                }
            }
        }
    }

}
