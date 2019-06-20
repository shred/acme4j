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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Problem;

/**
 * Unit tests for {@link ProblemBuilder}.
 */
public class ProblemBuilderTest {

    /**
     * Test building problems by error text.
     */
    @Test
    public void testBuilderByError() throws MalformedURLException, URISyntaxException {
        URL baseUrl = new URL("https://mock.test/resource");
        URL instanceUrl = new URL("https://mock.test/newaccount.html");

        Problem problem = new ProblemBuilder(baseUrl)
                .error("accountDoesNotExist")
                .detail("account does not exist")
                .instance(instanceUrl)
                .build();

        assertThat(problem.getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        assertThat(problem.getDetail(), is("account does not exist"));
        assertThat(problem.getInstance(), is(instanceUrl.toURI()));
    }

    /**
     * Test building problems by error text with prefix.
     */
    @Test
    public void testBuilderByUrnError() throws MalformedURLException, URISyntaxException {
        URL baseUrl = new URL("https://mock.test/resource");
        URL instanceUrl = new URL("https://mock.test/newaccount.html");

        Problem problem = new ProblemBuilder(baseUrl)
                .error("urn:ietf:params:acme:error:accountDoesNotExist")
                .detail("account does not exist")
                .instance(instanceUrl)
                .build();

        assertThat(problem.getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        assertThat(problem.getDetail(), is("account does not exist"));
        assertThat(problem.getInstance(), is(instanceUrl.toURI()));
    }

    /**
     * Test building problems by error type.
     */
    @Test
    public void testBuilderByType() throws MalformedURLException, URISyntaxException {
        URL baseUrl = new URL("https://mock.test/resource");
        URL instanceUrl = new URL("https://mock.test/newaccount.html");
        URI type = URI.create("urn:ietf:params:acme:error:accountDoesNotExist");

        Problem problem = new ProblemBuilder(baseUrl)
                .type(type)
                .detail("account does not exist")
                .instance(instanceUrl)
                .build();

        assertThat(problem.getType(), is(type));
        assertThat(problem.getDetail(), is("account does not exist"));
        assertThat(problem.getInstance(), is(instanceUrl.toURI()));
    }

    /**
     * Test building of complex problems with subproblems.
     */
    @Test
    public void testSubProblem() throws MalformedURLException, URISyntaxException {
        URL baseUrl = new URL("https://mock.test/resource");
        Identifier identifier1 = Identifier.dns("example.org");
        Identifier identifier2 = Identifier.dns("www.example.org");

        Problem sub1 = new ProblemBuilder(baseUrl)
                .error("connection")
                .identifier(identifier1)
                .build();

        Problem sub2 = new ProblemBuilder(baseUrl)
                .error("incorrectResponse")
                .identifier(identifier2)
                .build();

        Problem problem = new ProblemBuilder(baseUrl)
                .error("compound")
                .sub(sub1)
                .sub(sub2)
                .build();

        assertThat(problem.getType(), is(URI.create("urn:ietf:params:acme:error:compound")));
        assertThat(problem.getSubProblems().size(), is(2));

        Problem test1 = problem.getSubProblems().get(0);
        assertThat(test1.getType(), is(URI.create("urn:ietf:params:acme:error:connection")));
        assertThat(test1.getIdentifier(), is(identifier1));

        Problem test2 = problem.getSubProblems().get(1);
        assertThat(test2.getType(), is(URI.create("urn:ietf:params:acme:error:incorrectResponse")));
        assertThat(test2.getIdentifier(), is(identifier2));
    }

}