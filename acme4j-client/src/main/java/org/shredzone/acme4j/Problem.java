/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j;

import java.io.Serializable;
import java.net.URI;

import org.shredzone.acme4j.util.JSON;

/**
 * Represents a JSON Problem.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7807">RFC 7807</a>
 */
public class Problem implements Serializable {
    private static final long serialVersionUID = -8418248862966754214L;

    private final JSON problemJson;

    /**
     * Creates a new {@link Problem} object.
     *
     * @param problem
     *            Problem as JSON structure
     */
    public Problem(JSON problem) {
        this.problemJson = problem;
    }

    /**
     * Returns the problem type.
     */
    public URI getType() {
        return problemJson.get("type").asURI();
    }

    /**
     * Returns a human-readable description of the problem.
     */
    public String getDetail() {
        return problemJson.get("detail").asString();
    }

    /**
     * Returns the problem as {@link JSON} object, to access other fields.
     */
    public JSON asJSON() {
        return problemJson;
    }

    /**
     * Returns the problem as JSON string.
     */
    @Override
    public String toString() {
        return problemJson.toString();
    }

}
