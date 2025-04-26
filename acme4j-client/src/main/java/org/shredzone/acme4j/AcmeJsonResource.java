/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import java.io.Serial;
import java.net.URL;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.toolbox.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An extension of {@link AcmeResource} that also contains the current state of a resource
 * as JSON document. If the current state is not present, this class takes care of
 * fetching it from the server if necessary.
 */
public abstract class AcmeJsonResource extends AcmeResource {
    @Serial
    private static final long serialVersionUID = -5060364275766082345L;
    private static final Logger LOG = LoggerFactory.getLogger(AcmeJsonResource.class);

    private @Nullable JSON data = null;
    private @Nullable Instant retryAfter = null;

    /**
     * Create a new {@link AcmeJsonResource}.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param location
     *            Location {@link URL} of this resource
     */
    protected AcmeJsonResource(Login login, URL location) {
        super(login, location);
    }

    /**
     * Returns the JSON representation of the resource data.
     * <p>
     * If there is no data, {@link #fetch()} is invoked to fetch it from the server.
     * <p>
     * This method can be used to read proprietary data from the resources.
     *
     * @return Resource data, as {@link JSON}.
     * @throws AcmeLazyLoadingException
     *         if an {@link AcmeException} occured while fetching the current state from
     *         the server.
     */
    public JSON getJSON() {
        if (data == null) {
            try {
                fetch();
            } catch (AcmeException ex) {
                throw new AcmeLazyLoadingException(this, ex);
            }
        }
        return Objects.requireNonNull(data);
    }

    /**
     * Sets the JSON representation of the resource data.
     *
     * @param data
     *            New {@link JSON} data, must not be {@code null}.
     */
    protected void setJSON(JSON data) {
        invalidate();
        this.data = Objects.requireNonNull(data, "data");
    }

    /**
     * Checks if this resource is valid.
     *
     * @return {@code true} if the resource state has been loaded from the server. If
     *         {@code false}, {@link #getJSON()} would implicitly call {@link #fetch()}
     *         to fetch the current state from the server.
     */
    protected boolean isValid() {
        return data != null;
    }

    /**
     * Invalidates the state of this resource. Enforces a {@link #fetch()} when
     * {@link #getJSON()} is invoked.
     * <p>
     * Subclasses can override this method to purge internal caches that are based on the
     * JSON structure. Remember to invoke {@code super.invalidate()}!
     */
    protected void invalidate() {
        data = null;
        retryAfter = null;
    }

    /**
     * Updates this resource, by fetching the current resource data from the server.
     *
     * @return An {@link Optional} estimation when the resource status will change. If you
     * are polling for the resource to complete, you should wait for the given instant
     * before trying again. Empty if the server did not return a "Retry-After" header.
     * @throws AcmeException
     *         if the resource could not be fetched.
     * @since 3.2.0
     */
    public Optional<Instant> fetch() throws AcmeException {
        var resourceType = getClass().getSimpleName();
        LOG.debug("update {}", resourceType);
        try (var conn = getSession().connect()) {
            conn.sendSignedPostAsGetRequest(getLocation(), getLogin());
            setJSON(conn.readJsonResponse());
            var retryAfterOpt = conn.getRetryAfter();
            retryAfterOpt.ifPresent(instant -> LOG.debug("Retry-After: {}", instant));
            setRetryAfter(retryAfterOpt.orElse(null));
            return retryAfterOpt;
        }
    }

    /**
     * Sets a Retry-After instant.
     *
     * @since 3.2.0
     */
    protected void setRetryAfter(@Nullable Instant retryAfter) {
        this.retryAfter = retryAfter;
    }

    /**
     * Gets an estimation when the resource status will change. If you are polling for
     * the resource to complete, you should wait for the given instant before trying
     * a status refresh.
     * <p>
     * This instant was sent with the Retry-After header at the last update.
     *
     * @return Retry-after {@link Instant}, or empty if there was no such header.
     * @since 3.2.0
     */
    public Optional<Instant> getRetryAfter() {
        return Optional.ofNullable(retryAfter);
    }

}
