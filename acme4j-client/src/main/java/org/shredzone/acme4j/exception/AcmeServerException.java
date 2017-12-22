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
import java.util.Objects;

import org.shredzone.acme4j.Problem;

/**
 * An exception that is thrown when the ACME server returned an error. It contains
 * further details of the cause.
 */
public class AcmeServerException extends AcmeException {
    private static final long serialVersionUID = 5971622508467042792L;

    private final Problem problem;

    /**
     * Creates a new {@link AcmeServerException}.
     *
     * @param problem
     *            {@link Problem} that caused the exception
     */
    public AcmeServerException(Problem problem) {
        super(Objects.requireNonNull(problem).toString());
        this.problem = problem;
    }

    /**
     * Returns the error type.
     */
    public URI getType() {
        return problem.getType();
    }

    /**
     * Returns the {@link Problem} that caused the exception
     */
    public Problem getProblem() {
        return problem;
    }

}
