/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static java.util.stream.Collectors.toList;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A builder for {@link Problem} instances.
 * <p>
 * I had a problem so I thought to use Java. Now I have a {@link ProblemBuilder}. ;-)
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class ProblemBuilder {
    private static final String ACME_NAMESPACE = "urn:ietf:params:acme:error:";

    private final URL baseUrl;
    private final JSONBuilder json = new JSONBuilder();
    private final List<Problem> subproblems = new ArrayList<>();

    /**
     * Creates a new {@link ProblemBuilder}.
     *
     * @param baseUrl
     *         Base {@link URL}, usually the request {@link URL} that has lead to this
     *         problem.
     */
    public ProblemBuilder(URL baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Problem type.
     *
     * @param type
     *         Generic type of the problem (e.g. {@code "urn:ietf:params:acme:error:badCSR"}).
     */
    public ProblemBuilder type(URI type) {
        json.put("type", type);
        return this;
    }

    /**
     * ACME specific type of the problem. This is a convenience call for {@link
     * #type(URI)} which prepends the ACME namespace to the error.
     *
     * @param error
     *         ACME specific error (e.g. {@code "badCSR"}).
     */
    public ProblemBuilder error(String error) {
        return type(URI.create(error.startsWith("urn:") ? error : ACME_NAMESPACE + error));
    }

    /**
     * Human-readable short summary of the problem.
     *
     * @param detail
     *         Detail
     */
    public ProblemBuilder detail(String detail) {
        json.put("detail", detail);
        return this;
    }

    /**
     * An instance URL.
     *
     * @param instance
     *         Instance {@link URL}
     */
    public ProblemBuilder instance(URL instance) {
        json.put("instance", instance);
        return this;
    }

    /**
     * The {@link Identifier} this problem is related to. The identifier should only be
     * used in subproblems.
     *
     * @param identifier
     *         {@link Identifier} this problem is related to
     */
    public ProblemBuilder identifier(Identifier identifier) {
        json.put("identifier", identifier.toMap());
        return this;
    }

    /**
     * Appends a subproblem to this problem.
     *
     * @param sub
     *         Sub {@link Problem} to append
     */
    public ProblemBuilder sub(Problem sub) {
        subproblems.add(sub);
        return this;
    }

    /**
     * Builds a {@link Problem} from the parameters given.
     *
     * @return {@link Problem} that was built
     */
    public Problem build() {
        if (!subproblems.isEmpty()) {
            json.array("subproblems", subproblems.stream()
                    .map(Problem::asJSON)
                    .map(JSON::toMap)
                    .collect(toList())
            );
        }
        return new Problem(json.toJSON(), baseUrl);
    }

}
