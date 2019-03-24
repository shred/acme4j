/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.createProblem;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.shredzone.acme4j.Problem;

/**
 * Unit tests for {@link AcmeRateLimitedException}.
 */
public class AcmeRateLimitedExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeRateLimitedException() {
        URI type = URI.create("urn:ietf:params:acme:error:rateLimited");
        String detail = "Too many requests per minute";
        Instant retryAfter = Instant.now().plus(Duration.ofMinutes(1));
        Collection<URL> documents = Arrays.asList(
                        url("http://example.com/doc1.html"),
                        url("http://example.com/doc2.html"));

        Problem problem = createProblem(type, detail, null);

        AcmeRateLimitedException ex
                = new AcmeRateLimitedException(problem, retryAfter, documents);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getRetryAfter(), is(retryAfter));
        assertThat(ex.getDocuments(), containsInAnyOrder(documents.toArray()));
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeRateLimitedException() {
        URI type = URI.create("urn:ietf:params:acme:error:rateLimited");
        String detail = "Too many requests per minute";

        Problem problem = createProblem(type, detail, null);

        AcmeRateLimitedException ex
                = new AcmeRateLimitedException(problem, null, null);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getRetryAfter(), nullValue());
        assertThat(ex.getDocuments(), nullValue());
    }

}
