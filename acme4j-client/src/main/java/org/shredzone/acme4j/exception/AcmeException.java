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

import java.io.Serial;

/**
 * The root class of all checked acme4j exceptions.
 */
public class AcmeException extends Exception {
    @Serial
    private static final long serialVersionUID = -2935088954705632025L;

    /**
     * Creates a generic {@link AcmeException}.
     */
    public AcmeException() {
        super();
    }

    /**
     * Creates a generic {@link AcmeException}.
     *
     * @param msg
     *            Description
     */
    public AcmeException(String msg) {
        super(msg);
    }

    /**
     * Creates a generic {@link AcmeException}.
     *
     * @param msg
     *            Description
     * @param cause
     *            {@link Throwable} that caused this exception
     */
    public AcmeException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
