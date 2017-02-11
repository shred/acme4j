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
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;

/**
 * An exception that is thrown when a rate limit was exceeded.
 */
public class AcmeRateLimitExceededException extends AcmeServerException {
    private static final long serialVersionUID = 4150484059796413069L;

    private final Instant retryAfter;
    private final Collection<URI> documents;

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
     * @param documents
     *            URIs pointing to documents about the rate limit that was hit
     */
    public AcmeRateLimitExceededException(String type, String detail, Instant retryAfter, Collection<URI> documents) {
        super(type, detail);
        this.retryAfter = retryAfter;
        this.documents =
                documents != null ? Collections.unmodifiableCollection(documents) : null;
    }

    /**
     * Returns the moment the request is expected to succeed again. {@code null} if this
     * moment is not known.
     */
    public Instant getRetryAfter() {
        return retryAfter;
    }

    /**
     * Collection of URIs pointing to documents about the rate limit that was hit.
     * {@code null} if the server did not provide such URIs.
     */
    public Collection<URI> getDocuments() {
        return documents;
    }

}
