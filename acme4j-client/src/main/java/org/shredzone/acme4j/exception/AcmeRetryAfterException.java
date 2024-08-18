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

import java.time.Instant;
import java.util.Objects;

import org.shredzone.acme4j.AcmeJsonResource;

/**
 * A server side process has not been completed yet. The server also provides an estimate
 * of when the process is expected to complete.
 * <p>
 * Note: Prefer to use {@link AcmeJsonResource#fetch()}. Invoking
 * {@link AcmeJsonResource#update()} and catching this exception is unnecessary
 * complicated and a legacy from acme4j v2 which will disappear in a future release.
 *
 * @deprecated Will be removed in a future version.
 */
@Deprecated
public class AcmeRetryAfterException extends AcmeException {
    private static final long serialVersionUID = 4461979121063649905L;

    private final Instant retryAfter;

    /**
     * Creates a new {@link AcmeRetryAfterException}.
     *
     * @param msg
     *            Error details
     * @param retryAfter
     *            retry-after date returned by the server
     */
    public AcmeRetryAfterException(String msg, Instant retryAfter) {
        super(msg);
        this.retryAfter = Objects.requireNonNull(retryAfter);
    }

    /**
     * Returns the retry-after instant returned by the server. This is only an estimate
     * of when a retry attempt might succeed.
     */
    public Instant getRetryAfter() {
        return retryAfter;
    }

}
