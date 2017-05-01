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

import java.util.Objects;

/**
 * An exception that is thrown when the ACME server returned an error. It contains
 * further details of the cause.
 */
public class AcmeServerException extends AcmeException {
    private static final long serialVersionUID = 5971622508467042792L;

    private final String type;

    /**
     * Creates a new {@link AcmeServerException}.
     *
     * @param type
     *            System readable error type (e.g.
     *            {@code "urn:ietf:params:acme:error:malformed"})
     * @param detail
     *            Human readable error message
     */
    public AcmeServerException(String type, String detail) {
        super(detail);
        this.type = Objects.requireNonNull(type, "type");
    }

    /**
     * Returns the error type.
     */
    public String getType() {
        return type;
    }

}
