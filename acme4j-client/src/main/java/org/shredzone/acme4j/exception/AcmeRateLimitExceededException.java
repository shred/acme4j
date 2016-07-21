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

import java.util.Date;

/**
 * An exception that is thrown when a rate limit was exceeded.
 */
public class AcmeRateLimitExceededException extends AcmeServerException {
    private static final long serialVersionUID = 4150484059796413069L;

    private final Date retryAfter;

    /**
     * Creates a new {@link AcmeRateLimitExceededException}.
     *
     * @param type
     *            System readable error type (here
     *            {@code "urn:ietf:params:acme:error:rateLimited"})
     * @param detail
     *            Human readable error message
     * @param retryAfter
     *            The moment the request is expected to succeed again, may be {@code null}
     *            if not known
     */
    public AcmeRateLimitExceededException(String type, String detail, Date retryAfter) {
        super(type, detail);
        this.retryAfter = retryAfter;
    }

    /**
     * Returns the moment the request is expected to succeed again. {@code null} if this
     * moment is not known.
     */
    public Date getRetryAfter() {
        return (retryAfter != null ? new Date(retryAfter.getTime()) : null);
    }

}
