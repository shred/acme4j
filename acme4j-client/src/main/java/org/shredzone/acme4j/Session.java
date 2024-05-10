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

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.time.ZonedDateTime;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.StreamSupport;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.GenericAcmeProvider;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;

/**
 * A {@link Session} tracks the entire communication with a CA.
 * <p>
 * To create a session instance, use its constructor. It requires the URI of the ACME
 * server to connect to. This can be the location of the CA's directory (via {@code http}
 * or {@code https} protocol), or a special URI (via {@code acme} protocol). See the
 * documentation about valid URIs.
 */
public class Session {

    private static final GenericAcmeProvider GENERIC_PROVIDER = new GenericAcmeProvider();

    private final AtomicReference<Map<Resource, URL>> resourceMap = new AtomicReference<>();
    private final AtomicReference<Metadata> metadata = new AtomicReference<>();
    private final NetworkSettings networkSettings = new NetworkSettings();
    private final URI serverUri;
    private final AcmeProvider provider;

    private @Nullable String nonce;
    private @Nullable Locale locale = Locale.getDefault();
    private String languageHeader = AcmeUtils.localeToLanguageHeader(Locale.getDefault());
    protected @Nullable ZonedDateTime directoryLastModified;
    protected @Nullable ZonedDateTime directoryExpires;

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *         URI string of the ACME server to connect to. This is either the location of
     *         the CA's ACME directory (using {@code http} or {@code https} protocol), or
     *         a special URI (using the {@code acme} protocol).
     * @throws IllegalArgumentException
     *         if no ACME provider was found for the server URI.
     */
    public Session(String serverUri) {
        this(URI.create(serverUri));
    }

    /**
     * Creates a new {@link Session}.
     *
     * @param serverUri
     *         {@link URI} of the ACME server to connect to. This is either the location
     *         of the CA's ACME directory (using {@code http} or {@code https} protocol),
     *         or a special URI (using the {@code acme} protocol).
     * @throws IllegalArgumentException
     *         if no ACME provider was found for the server URI.
     */
    public Session(URI serverUri) {
        this.serverUri = requireNonNull(serverUri, "serverUri");

        if (GENERIC_PROVIDER.accepts(serverUri)) {
            provider = GENERIC_PROVIDER;
            return;
        }

        var providers = ServiceLoader.load(AcmeProvider.class);
        provider = StreamSupport.stream(providers.spliterator(), false)
            .filter(p -> p.accepts(serverUri))
            .reduce((a, b) -> {
                    throw new IllegalArgumentException("Both ACME providers "
                        + a.getClass().getSimpleName() + " and "
                        + b.getClass().getSimpleName() + " accept "
                        + serverUri + ". Please check your classpath.");
                })
            .orElseThrow(() -> new IllegalArgumentException("No ACME provider found for " + serverUri));
    }

    /**
     * Creates a new {@link Session} using the given {@link AcmeProvider}.
     * <p>
     * This constructor is only to be used for testing purposes.
     *
     * @param serverUri
     *         {@link URI} of the ACME server
     * @param provider
     *         {@link AcmeProvider} to be used
     * @since 2.8
     */
    public Session(URI serverUri, AcmeProvider provider) {
        this.serverUri = requireNonNull(serverUri, "serverUri");
        this.provider = requireNonNull(provider, "provider");

        if (!provider.accepts(serverUri)) {
            throw new IllegalArgumentException("Provider does not accept " + serverUri);
        }
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
     * Gets the last base64 encoded nonce, or {@code null} if the session is new. This
     * method is mainly for internal use.
     */
    @Nullable
    public String getNonce() {
        return nonce;
    }

    /**
     * Sets the base64 encoded nonce received by the server. This method is mainly for
     * internal use.
     */
    public void setNonce(@Nullable String nonce) {
        this.nonce = nonce;
    }

    /**
     * Gets the current locale of this session, or {@code null} if no special language is
     * selected.
     */
    @Nullable
    public Locale getLocale() {
        return locale;
    }

    /**
     * Sets the locale used in this session. The locale is passed to the server as
     * Accept-Language header. The server <em>may</em> respond with localized messages.
     * The default is the system's language. If set to {@code null}, any language will be
     * accepted.
     */
    public void setLocale(@Nullable Locale locale) {
        this.locale = locale;
        this.languageHeader = AcmeUtils.localeToLanguageHeader(locale);
    }

    /**
     * Gets an Accept-Language header value that matches the current locale. This method
     * is mainly for internal use.
     *
     * @since 3.0.0
     */
    public String getLanguageHeader() {
        return languageHeader;
    }

    /**
     * Returns the current {@link NetworkSettings}.
     *
     * @return {@link NetworkSettings}
     * @since 2.8
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")    // behavior is intended
    public NetworkSettings networkSettings() {
        return networkSettings;
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
     * Returns a new {@link Connection} to the ACME server.
     *
     * @return {@link Connection}
     */
    public Connection connect() {
        return provider.connect(getServerUri(), networkSettings);
    }

    /**
     * Gets the {@link URL} of the given {@link Resource}. This may involve connecting to
     * the server and fetching the directory. The result is cached.
     *
     * @param resource
     *            {@link Resource} to get the {@link URL} of
     * @return {@link URL} of the resource
     * @throws AcmeException
     *             if the server does not offer the {@link Resource}
     */
    public URL resourceUrl(Resource resource) throws AcmeException {
        return resourceUrlOptional(resource)
                .orElseThrow(() -> new AcmeNotSupportedException(resource.path()));
    }

    /**
     * Gets the {@link URL} of the given {@link Resource}. This may involve connecting to
     * the server and fetching the directory. The result is cached.
     *
     * @param resource
     *            {@link Resource} to get the {@link URL} of
     * @return {@link URL} of the resource, or empty if the resource is not available.
     * @since 3.0.0
     */
    public Optional<URL> resourceUrlOptional(Resource resource) throws AcmeException {
        readDirectory();
        return Optional.ofNullable(resourceMap.get()
                .get(requireNonNull(resource, "resource")));
    }

    /**
     * Gets the metadata of the provider's directory. This may involve connecting to the
     * server and fetching the directory. The result is cached.
     *
     * @return {@link Metadata}. May contain no data, but is never {@code null}.
     */
    public Metadata getMetadata() throws AcmeException {
        readDirectory();
        return metadata.get();
    }

    /**
     * Returns the date when the directory has been modified the last time.
     *
     * @return The last modification date of the directory, or {@code null} if unknown
     * (directory has not been read yet or did not provide this information).
     * @since 2.10
     */
    @Nullable
    public ZonedDateTime getDirectoryLastModified() {
        return directoryLastModified;
    }

    /**
     * Sets the date when the directory has been modified the last time. Should only be
     * invoked by {@link AcmeProvider} implementations.
     *
     * @param directoryLastModified
     *         The last modification date of the directory, or {@code null} if unknown
     *         (directory has not been read yet or did not provide this information).
     * @since 2.10
     */
    public void setDirectoryLastModified(@Nullable ZonedDateTime directoryLastModified) {
        this.directoryLastModified = directoryLastModified;
    }

    /**
     * Returns the date when the current directory records will expire. A fresh copy of
     * the directory will be fetched automatically after that instant.
     *
     * @return The expiration date, or {@code null} if the server did not provide this
     * information.
     * @since 2.10
     */
    @Nullable
    public ZonedDateTime getDirectoryExpires() {
        return directoryExpires;
    }

    /**
     * Sets the date when the current directory will expire. Should only be invoked by
     * {@link AcmeProvider} implementations.
     *
     * @param directoryExpires
     *         Expiration date, or {@code null} if the server did not provide this
     *         information.
     * @since 2.10
     */
    public void setDirectoryExpires(@Nullable ZonedDateTime directoryExpires) {
        this.directoryExpires = directoryExpires;
    }

    /**
     * Returns {@code true} if a copy of the directory is present in a local cache. It is
     * not evaluated if the cached copy has expired though.
     *
     * @return {@code true} if a directory is available.
     * @since 2.10
     */
    public boolean hasDirectory() {
        return resourceMap.get() != null;
    }

    /**
     * Purges the directory cache. Makes sure that a fresh copy of the directory will be
     * read from the CA on the next time the directory is accessed.
     *
     * @since 3.0.0
     */
    public void purgeDirectoryCache() {
        setDirectoryLastModified(null);
        setDirectoryExpires(null);
        resourceMap.set(null);
    }

    /**
     * Reads the provider's directory, then rebuild the resource map. The resource map
     * is unchanged if the {@link AcmeProvider} returns that the directory has not been
     * changed on the remote side.
     */
    private void readDirectory() throws AcmeException {
        var directoryJson = provider().directory(this, getServerUri());
        if (directoryJson == null) {
            if (!hasDirectory()) {
                throw new AcmeException("AcmeProvider did not provide a directory");
            }
            return;
        }

        var meta = directoryJson.get("meta");
        if (meta.isPresent()) {
            metadata.set(new Metadata(meta.asObject()));
        } else {
            metadata.set(new Metadata(JSON.empty()));
        }

        var map = new EnumMap<Resource, URL>(Resource.class);
        for (var res : Resource.values()) {
            directoryJson.get(res.path())
                    .map(Value::asURL)
                    .ifPresent(url -> map.put(res, url));
        }

        resourceMap.set(map);
    }

    @Override
    protected final void finalize() {
        // CT_CONSTRUCTOR_THROW: Prevents finalizer attack
    }

}
