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

import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Represents a JSON Problem.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7807">RFC 7807</a>
 */
public class Problem implements Serializable {
    private static final long serialVersionUID = -8418248862966754214L;

    private final URL baseUrl;
    private final JSON problemJson;

    /**
     * Creates a new {@link Problem} object.
     *
     * @param problem
     *            Problem as JSON structure
     * @param baseUrl
     *            Document's base {@link URL} to resolve relative URIs against
     */
    public Problem(JSON problem, URL baseUrl) {
        this.problemJson = problem;
        this.baseUrl = baseUrl;
    }

    /**
     * Returns the problem type. It is always an absolute URI.
     */
    public URI getType() {
        try {
            String type = problemJson.get("type").asString();
            return type != null ? baseUrl.toURI().resolve(type) : null;
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Bad base URL", ex);
        }
    }

    /**
     * Returns a human-readable description of the problem.
     */
    public String getDetail() {
        return problemJson.get("detail").asString();
    }

    /**
     * Returns an URI that identifies the specific occurence of the problem. It is always
     * an absolute URI.
     */
    public URI getInstance() {
        try {
            String instance = problemJson.get("instance").asString();
            return instance != null ? baseUrl.toURI().resolve(instance) : null;
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Bad base URL", ex);
        }
    }

    /**
     * Returns the domain this problem relates to. May be {@code null}.
     */
    public String getDomain() {
        JSON identifier = problemJson.get("identifier").asObject();
        if (identifier == null) {
            return null;
        }

        String type = identifier.get("type").asString();
        if (!"dns".equals(type)) {
            throw new AcmeProtocolException("Cannot process a " + type + " identifier");
        }

        return identifier.get("value").asString();
    }

    /**
     * Returns a list of sub-problems. May be empty, but is never {@code null}.
     */
    public List<Problem> getSubProblems() {
        return unmodifiableList(
                problemJson.get("subproblems")
                        .asArray().stream()
                        .map(o -> o.asProblem(baseUrl))
                        .collect(toList())
        );
    }

    /**
     * Returns the problem as {@link JSON} object, to access other fields.
     *
     * @return Problem as {@link JSON} object
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
