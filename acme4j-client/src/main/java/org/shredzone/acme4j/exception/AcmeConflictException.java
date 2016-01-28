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

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.Registration;

/**
 * An exception that is thrown when there is a conflict with the request. For example,
 * this exception is thrown when {@link AcmeClient#newRegistration(Registration)}
 * is invoked, but the registration already exists.
 *
 * @author Richard "Shred" Körber
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
