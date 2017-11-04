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
package org.shredzone.acme4j.exception;

import java.net.URL;
import java.util.Objects;

/**
 * An exception that is thrown when there is a conflict with the request. For example,
 * this exception is thrown when a registration already exists.
 */
public class AcmeConflictException extends AcmeException {
    private static final long serialVersionUID = 7454201988845449591L;

    private final URL location;

    /**
     * Creates a new {@link AcmeConflictException}.
     *
     * @param msg
     *            Details about the conflicting resource
     * @param location
     *            {@link URL} of the conflicting resource
     */
    public AcmeConflictException(String msg, URL location) {
        super(msg);
        this.location = Objects.requireNonNull(location, "location");
    }

    /**
     * Location of the conflicting resource.
     */
    public URL getLocation() {
        return location;
    }

}
