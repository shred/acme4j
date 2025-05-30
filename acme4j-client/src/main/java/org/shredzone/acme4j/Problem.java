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

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;

/**
 * A JSON problem. It contains further, machine- and human-readable details about the
 * reason of an error or failure.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7807">RFC 7807</a>
 */
public class Problem implements Serializable {
    @Serial
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
        return problemJson.get("type")
                    .map(Value::asString)
                    .map(it -> {
                        try {
                            return baseUrl.toURI().resolve(it);
                        } catch (URISyntaxException ex) {
                            throw new IllegalArgumentException("Bad base URL", ex);
                        }
                    })
                    .orElseThrow(() -> new AcmeProtocolException("Problem without type"));
    }

    /**
     * Returns a short, human-readable summary of the problem. The text may be localized
     * if supported by the server. Empty if the server did not provide a title.
     *
     * @see #toString()
     */
    public Optional<String> getTitle() {
        return problemJson.get("title").map(Value::asString);
    }

    /**
     * Returns a detailed and specific human-readable explanation of the problem. The
     * text may be localized if supported by the server.
     *
     * @see #toString()
     */
    public Optional<String> getDetail() {
        return problemJson.get("detail").map(Value::asString);
    }

    /**
     * Returns a URI that identifies the specific occurence of the problem. It is always
     * an absolute URI.
     */
    public Optional<URI> getInstance() {
        return problemJson.get("instance")
                        .map(Value::asString)
                        .map(it ->  {
                            try {
                                return baseUrl.toURI().resolve(it);
                            } catch (URISyntaxException ex) {
                                throw new IllegalArgumentException("Bad base URL", ex);
                            }
                        });
    }

    /**
     * Returns the {@link Identifier} this problem relates to.
     *
     * @since 2.3
     */
    public Optional<Identifier> getIdentifier() {
        return problemJson.get("identifier")
                        .optional()
                        .map(Value::asIdentifier);
    }

    /**
     * Returns a list of sub-problems.
     */
    public List<Problem> getSubProblems() {
        return problemJson.get("subproblems")
                        .asArray()
                        .stream()
                        .map(o -> o.asProblem(baseUrl))
                        .toList();
    }

    /**
     * Returns the problem as {@link JSON} object, to access other, non-standard fields.
     *
     * @return Problem as {@link JSON} object
     */
    public JSON asJSON() {
        return problemJson;
    }

    /**
     * Returns a human-readable description of the problem, that is as specific as
     * possible. The description may be localized if supported by the server.
     * <p>
     * If {@link #getSubProblems()} exist, they will be appended.
     * <p>
     * Technically, it returns {@link #getDetail()}. If not set, {@link #getTitle()} is
     * returned instead. As a last resort, {@link #getType()} is returned.
     */
    @Override
    public String toString() {
        var sb = new StringBuilder();

        if (getDetail().isPresent()) {
            sb.append(getDetail().get());
        } else if (getTitle().isPresent()) {
            sb.append(getTitle().get());
        } else {
            sb.append(getType());
        }

        var subproblems = getSubProblems();

        if (!subproblems.isEmpty()) {
            sb.append(" (");
            var first = true;
            for (var sub : subproblems) {
                if (!first) {
                    sb.append(" ‒ ");
                }
                sb.append(sub.toString());
                first = false;
            }
            sb.append(')');
        }

        return sb.toString();
    }

}
