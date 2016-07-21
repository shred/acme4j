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

import java.net.URI;

/**
 * An exception that is thrown when there is a conflict with the request. For example,
 * this exception is thrown when a registration already exists.
 */
public class AcmeConflictException extends AcmeException {
    private static final long serialVersionUID = 7454201988845449591L;

    private final URI location;

    public AcmeConflictException(String msg, URI location) {
        super(msg);
        this.location = location;
    }

    /**
     * Location of the conflicting resource.
     */
    public URI getLocation() {
        return location;
    }

}
