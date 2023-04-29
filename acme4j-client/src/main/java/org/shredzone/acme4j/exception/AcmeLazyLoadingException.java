/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.exception;

import static java.util.Objects.requireNonNull;

import java.net.URL;

import org.shredzone.acme4j.AcmeResource;

/**
 * A runtime exception that is thrown when an {@link AcmeException} occured while trying
 * to lazy-load a resource from the ACME server. It contains the original cause of the
 * exception and a reference to the resource that could not be lazy-loaded. It is usually
 * thrown by getter methods, so the API is not polluted with checked exceptions.
 */
public class AcmeLazyLoadingException extends RuntimeException {
    private static final long serialVersionUID = 1000353433913721901L;

    private final Class<? extends AcmeResource> type;
    private final URL location;

    /**
     * Creates a new {@link AcmeLazyLoadingException}.
     *
     * @param resource
     *            {@link AcmeResource} to be loaded
     * @param cause
     *            {@link AcmeException} that was raised
     */
    public AcmeLazyLoadingException(AcmeResource resource, AcmeException cause) {
        this(requireNonNull(resource).getClass(), requireNonNull(resource).getLocation(), cause);
    }

    /**
     * Creates a new {@link AcmeLazyLoadingException}.
     * <p>
     * This constructor is used if there is no actual instance of the resource.
     *
     * @param type
     *         {@link AcmeResource} type to be loaded
     * @param location
     *         Resource location
     * @param cause
     *         {@link AcmeException} that was raised
     * @since 2.8
     */
    public AcmeLazyLoadingException(Class<? extends AcmeResource> type, URL location, AcmeException cause) {
        super(requireNonNull(type).getSimpleName() + " " + requireNonNull(location), requireNonNull(cause));
        this.type = type;
        this.location = location;
    }

    /**
     * Returns the {@link AcmeResource} type of the resource that could not be loaded.
     */
    public Class<? extends AcmeResource> getType() {
        return type;
    }

    /**
     * Returns the location of the resource that could not be loaded.
     */
    public URL getLocation() {
        return location;
    }

}
