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

    private final URI baseUri;
    private final JSON problem;

    /**
     * Creates a new {@link Problem} object.
     *
     * @param problem
     *            Problem as JSON structure
     * @param baseUri
     *            Document's base {@link URI} to resolve relative URIs against
     */
    public Problem(JSON problem, URI baseUri) {
        this.problem = problem;
        this.baseUri = baseUri;
    }

    /**
     * Returns the problem type. It is always an absolute URI.
     */
    public URI getType() {
        String type = problem.get("type").asString();
        return type != null ? baseUri.resolve(type) : null;
    }

    /**
     * Returns a human-readable description of the problem.
     */
    public String getDetail() {
        return problem.get("detail").asString();
    }

    /**
     * Returns an URI that identifies the specific occurence of the problem. It is always
     * an absolute URI.
     */
    public URI getInstance() {
        String instance = problem.get("instance").asString();
        return instance != null ? baseUri.resolve(instance) : null;
    }

    /**
     * Returns the problem as {@link JSON} object, to access other fields.
     */
    public JSON asJSON() {
        return problem;
    }

    /**
     * Returns the problem as JSON string.
     */
    @Override
    public String toString() {
        return problem.toString();
    }

}
