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
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;

import org.shredzone.acme4j.Problem;

/**
 * An exception that is thrown when a rate limit was exceeded.
 */
public class AcmeRateLimitedException extends AcmeServerException {
    private static final long serialVersionUID = 4150484059796413069L;

    private final Instant retryAfter;
    private final Collection<URL> documents;

    /**
     * Creates a new {@link AcmeRateLimitedException}.
     *
     * @param problem
     *            {@link Problem} that caused the exception
     * @param retryAfter
     *            The moment the request is expected to succeed again, may be {@code null}
     *            if not known
     * @param documents
     *            URLs pointing to documents about the rate limit that was hit
     */
    public AcmeRateLimitedException(Problem problem, Instant retryAfter, Collection<URL> documents) {
        super(problem);
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
     * Collection of URLs pointing to documents about the rate limit that was hit.
     * {@code null} if the server did not provide such URLs.
     */
    public Collection<URL> getDocuments() {
        return documents;
    }

}
