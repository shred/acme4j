/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
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
 * A runtime exception that is thrown if the ACME server does not support a certain
 * feature. It might be either because that feature is optional, or because the server
 * is not fully RFC compliant.
 */
public class AcmeNotSupportedException extends AcmeProtocolException {
    @Serial
    private static final long serialVersionUID = 3434074002226584731L;

    /**
     * Creates a new {@link AcmeNotSupportedException}.
     *
     * @param feature
     *            Feature that is not supported
     */
    public AcmeNotSupportedException(String feature) {
        super("Server does not support " + feature);
    }

}
