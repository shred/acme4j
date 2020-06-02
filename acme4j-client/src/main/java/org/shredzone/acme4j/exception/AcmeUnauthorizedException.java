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

import org.shredzone.acme4j.Problem;

/**
 * An exception that is thrown when the client is not authorized. The details will give
 * an explanation for the reasons (e.g. "client not on a whitelist").
 */
public class AcmeUnauthorizedException extends AcmeServerException {
    private static final long serialVersionUID = 9064697508262919366L;

    /**
     * Creates a new {@link AcmeUnauthorizedException}.
     *
     * @param problem
     *            {@link Problem} that caused the exception
     */
    public AcmeUnauthorizedException(Problem problem) {
        super(problem);
    }

}
