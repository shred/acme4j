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

import static org.assertj.core.api.Assertions.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.createProblem;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AcmeRateLimitedException}.
 */
public class AcmeRateLimitedExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeRateLimitedException() {
        var type = URI.create("urn:ietf:params:acme:error:rateLimited");
        var detail = "Too many requests per minute";
        var retryAfter = Instant.now().plus(Duration.ofMinutes(1));
        var documents = Arrays.asList(
                        url("http://example.com/doc1.html"),
                        url("http://example.com/doc2.html"));

        var problem = createProblem(type, detail, null);

        var ex = new AcmeRateLimitedException(problem, retryAfter, documents);

        assertThat(ex.getType()).isEqualTo(type);
        assertThat(ex.getMessage()).isEqualTo(detail);
        assertThat(ex.getRetryAfter().orElseThrow()).isEqualTo(retryAfter);
        assertThat(ex.getDocuments()).containsAll(documents);
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeRateLimitedException() {
        var type = URI.create("urn:ietf:params:acme:error:rateLimited");
        var detail = "Too many requests per minute";

        var problem = createProblem(type, detail, null);

        var ex = new AcmeRateLimitedException(problem, null, null);

        assertThat(ex.getType()).isEqualTo(type);
        assertThat(ex.getMessage()).isEqualTo(detail);
        assertThat(ex.getRetryAfter()).isEmpty();
        assertThat(ex.getDocuments()).isEmpty();
    }

}
