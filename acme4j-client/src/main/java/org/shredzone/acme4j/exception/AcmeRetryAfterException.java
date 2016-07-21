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

import java.util.Date;

/**
 * This exception is thrown when a server side process has not been completed yet, and the
 * server returned an estimated retry date.
 */
public class AcmeRetryAfterException extends AcmeException {
    private static final long serialVersionUID = 4461979121063649905L;

    private final Date retryAfter;

    public AcmeRetryAfterException(String msg, Date retryAfter) {
        super(msg);
        this.retryAfter = retryAfter;
    }

    /**
     * Returns the retry-after date returned by the server.
     */
    public Date getRetryAfter() {
        return (retryAfter != null ? new Date(retryAfter.getTime()) : null);
    }

}
