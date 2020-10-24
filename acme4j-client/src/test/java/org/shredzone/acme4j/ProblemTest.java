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

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.URI;
import java.net.URL;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Problem}.
 */
public class ProblemTest {

    @Test
    public void testProblem() {
        URL baseUrl = url("https://example.com/acme/1");
        JSON original = TestUtils.getJSON("problem");

        Problem problem = new Problem(original, baseUrl);

        assertThat(problem.getType(), is(URI.create("urn:ietf:params:acme:error:malformed")));
        assertThat(problem.getTitle(), is("Some of the identifiers requested were rejected"));
        assertThat(problem.getDetail(), is("Identifier \"abc12_\" is malformed"));
        assertThat(problem.getInstance(), is(URI.create("https://example.com/documents/error.html")));
        assertThat(problem.getIdentifier(), is(nullValue()));
        assertThat(problem.asJSON().toString(), is(sameJSONAs(original.toString())));
        assertThat(problem.toString(), is(
                "Identifier \"abc12_\" is malformed ("
                + "Invalid underscore in DNS name \"_example.com\" ‒ "
                + "This CA will not issue for \"example.net\")"));

        List<Problem> subs = problem.getSubProblems();
        assertThat(subs, not(nullValue()));
        assertThat(subs, hasSize(2));

        Problem p1 = subs.get(0);
        assertThat(p1.getType(), is(URI.create("urn:ietf:params:acme:error:malformed")));
        assertThat(p1.getTitle(), is(nullValue()));
        assertThat(p1.getDetail(), is("Invalid underscore in DNS name \"_example.com\""));
        assertThat(p1.getIdentifier().getDomain(), is("_example.com"));
        assertThat(p1.toString(), is("Invalid underscore in DNS name \"_example.com\""));

        Problem p2 = subs.get(1);
        assertThat(p2.getType(), is(URI.create("urn:ietf:params:acme:error:rejectedIdentifier")));
        assertThat(p2.getTitle(), is(nullValue()));
        assertThat(p2.getDetail(), is("This CA will not issue for \"example.net\""));
        assertThat(p2.getIdentifier().getDomain(), is("example.net"));
        assertThat(p2.toString(), is("This CA will not issue for \"example.net\""));
    }

    /**
     * Test that {@link Problem#toString()} always returns the most specific message.
     */
    @Test
    public void testToString() {
        URL baseUrl = url("https://example.com/acme/1");
        URI typeUri = URI.create("urn:ietf:params:acme:error:malformed");

        JSONBuilder jb = new JSONBuilder();

        jb.put("type", typeUri);
        Problem p1 = new Problem(jb.toJSON(), baseUrl);
        assertThat(p1.toString(), is(typeUri.toString()));

        jb.put("title", "Some of the identifiers requested were rejected");
        Problem p2 = new Problem(jb.toJSON(), baseUrl);
        assertThat(p2.toString(), is("Some of the identifiers requested were rejected"));

        jb.put("detail", "Identifier \"abc12_\" is malformed");
        Problem p3 = new Problem(jb.toJSON(), baseUrl);
        assertThat(p3.toString(), is("Identifier \"abc12_\" is malformed"));
    }

}
