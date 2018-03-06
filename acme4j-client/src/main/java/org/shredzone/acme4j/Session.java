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

import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.StreamSupport;

import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A session stores the ACME server URI. It also tracks communication parameters.
 */
public class Session {
    private final AtomicReference<Map<Resource, URL>> resourceMap = new AtomicReference<>();
    private final AtomicReference<Metadata> metadata = new AtomicReference<>();
    private final URI serverUri;
    private final AcmeProvider provider;

    private String nonce;
    private Locale locale = Locale.getDefault();
    private Proxy proxy = Proxy.NO_PROXY;
    protected Instant directoryCacheExpiry;

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *            URI string of the ACME server
     */
    public Session(String serverUri) {
        this(URI.create(serverUri));
    }

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *            {@link URI} of the ACME server
     * @throws IllegalArgumentException
     *             if no ACME provider was found for the server URI.
     */
    public Session(URI serverUri) {
        this.serverUri = Objects.requireNonNull(serverUri, "serverUri");

        final URI localServerUri = serverUri;

        Iterable<AcmeProvider> providers = ServiceLoader.load(AcmeProvider.class);
        provider = StreamSupport.stream(providers.spliterator(), false)
            .filter(p -> p.accepts(localServerUri))
            .reduce((a, b) -> {
                    throw new IllegalArgumentException("Both ACME providers "
                        + a.getClass().getSimpleName() + " and "
                        + b.getClass().getSimpleName() + " accept "
                        + localServerUri + ". Please check your classpath.");
                })
            .orElseThrow(() -> new IllegalArgumentException("No ACME provider found for " + localServerUri));
    }

    /**
     * Logs into an existing account.
     *
     * @param accountLocation
     *            Location {@link URL} of the account
     * @param accountKeyPair
     *            Account {@link KeyPair}
     * @return {@link Login} to this account
     */
    public Login login(URL accountLocation, KeyPair accountKeyPair) {
        return new Login(accountLocation, accountKeyPair, this);
    }

    /**
     * Gets the ACME server {@link URI} of this session.
     */
    public URI getServerUri() {
        return serverUri;
    }

    /**
     * Gets the last base64 encoded nonce, or {@code null} if the session is new.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Sets the base64 encoded nonce received by the server.
     */
    public void setNonce(String nonce) {
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
     * Gets the {@link Proxy} to be used for connections.
     */
    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Sets a {@link Proxy} that is to be used for all connections. If {@code null},
     * {@link Proxy#NO_PROXY} is used, which is also the default.
     */
    public void setProxy(Proxy proxy) {
        this.proxy = proxy != null ? proxy : Proxy.NO_PROXY;
    }

    /**
     * Returns the {@link AcmeProvider} that is used for this session.
     *
     * @return {@link AcmeProvider}
     */
    public AcmeProvider provider() {
        return provider;
    }

    /**
     * Gets the {@link URL} of the given {@link Resource}. This may involve connecting to
     * the server and getting a directory. The result is cached.
     *
     * @param resource
     *            {@link Resource} to get the {@link URL} of
     * @return {@link URL}, or {@code null} if the server does not offer that resource
     */
    public URL resourceUrl(Resource resource) throws AcmeException {
        readDirectory();
        return resourceMap.get().get(Objects.requireNonNull(resource, "resource"));
    }

    /**
     * Gets the metadata of the provider's directory. This may involve connecting to the
     * server and getting a directory. The result is cached.
     *
     * @return {@link Metadata}. May contain no data, but is never {@code null}.
     */
    public Metadata getMetadata() throws AcmeException {
        readDirectory();
        return metadata.get();
    }

    /**
     * Reads the provider's directory, then rebuild the resource map. The response is
     * cached.
     */
    private void readDirectory() throws AcmeException {
        synchronized (this) {
            Instant now = Instant.now();
            if (directoryCacheExpiry != null && directoryCacheExpiry.isAfter(now)) {
                return;
            }
            directoryCacheExpiry = now.plus(Duration.ofHours(1));
        }

        JSON directoryJson = provider().directory(this, getServerUri());

        JSON meta = directoryJson.get("meta").asObject();
        if (meta != null) {
            metadata.set(new Metadata(meta));
        } else {
            metadata.set(new Metadata(JSON.empty()));
        }

        Map<Resource, URL> map = new EnumMap<>(Resource.class);
        for (Resource res : Resource.values()) {
            URL url = directoryJson.get(res.path()).asURL();
            if (url != null) {
                map.put(res, url);
            }
        }

        resourceMap.set(map);
    }

}
