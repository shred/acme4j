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

import org.shredzone.acme4j.connector.DefaultConnection;
import org.shredzone.acme4j.util.AcmeUtils;

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
        AcmeUtils.assertNotNull(type, "type");
        this.type = type;
    }

    /**
     * Returns the error type.
     */
    public String getType() {
        return type;
    }

    /**
     * Returns the ACME error type. This is the last part of the type URN, e.g.
     * {@code "malformed"} on {@code "urn:ietf:params:acme:error:malformed"}.
     *
     * @return ACME error type, or {@code null} if this is not an
     *         {@code "urn:ietf:params:acme:error"}
     */
    @SuppressWarnings("deprecation")
    public String getAcmeErrorType() {
        if (type.startsWith(DefaultConnection.ACME_ERROR_PREFIX)) {
            return type.substring(DefaultConnection.ACME_ERROR_PREFIX.length());
        } else if (type.startsWith(DefaultConnection.ACME_ERROR_PREFIX_DEPRECATED)) {
            return type.substring(DefaultConnection.ACME_ERROR_PREFIX_DEPRECATED.length());
        } else {
            return null;
        }
    }

}
