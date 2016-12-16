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
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.TokenChallenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.util.AcmeUtils;

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
    private Map<String, Object> directoryMap;
    private Metadata metadata;
    private Locale locale = Locale.getDefault();
    protected Date directoryCacheExpiry;

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
        AcmeUtils.assertNotNull(serverUri, "serverUri");
        AcmeUtils.assertNotNull(keyPair, "keyPair");

        this.serverUri = serverUri;
        this.keyPair = keyPair;
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
    public Challenge createChallenge(Map<String, Object> data) {
        AcmeUtils.assertNotNull(data, "data");

        String type = (String) data.get("type");
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("type must not be empty or null");
        }

        Challenge challenge = provider().createChallenge(this, type);
        if (challenge == null) {
            if (data.containsKey("token")) {
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
        AcmeUtils.assertNotNull(resource, "resource");
        readDirectory();
        return resourceMap.get(resource);
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
    @SuppressWarnings("unchecked")
    private void readDirectory() throws AcmeException {
        synchronized (this) {
            Date now = new Date();
            if (directoryMap == null || !directoryCacheExpiry.after(now)) {
                directoryMap = provider().directory(this, getServerUri());
                directoryCacheExpiry = new Date(now.getTime() + 60 * 60 * 1000L);

                Object meta = directoryMap.get("meta");
                if (meta != null && meta instanceof Map) {
                    metadata = new Metadata((Map<String, Object>) meta);
                } else {
                    metadata = new Metadata();
                }

                resourceMap.clear();
                for (Map.Entry<String, Object> entry : directoryMap.entrySet()) {
                    Resource res = Resource.parse(entry.getKey());
                    if (res != null) {
                        try {
                            resourceMap.put(res, new URI(entry.getValue().toString()));
                        } catch (URISyntaxException ex) {
                            throw new AcmeProtocolException("Illegal URI for resource " + res, ex);
                        }
                    }
                }
            }
        }
    }

}
