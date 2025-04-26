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

import java.io.IOException;
import java.io.Serial;

/**
 * A general network error has occured while communicating with the server (e.g. network
 * timeout).
 */
public class AcmeNetworkException extends AcmeException {
    @Serial
    private static final long serialVersionUID = 2054398693543329179L;

    /**
     * Create a new {@link AcmeNetworkException}.
     *
     * @param cause
     *            {@link IOException} that caused the network error
     */
    public AcmeNetworkException(IOException cause) {
        super("Network error", cause);
    }

}
