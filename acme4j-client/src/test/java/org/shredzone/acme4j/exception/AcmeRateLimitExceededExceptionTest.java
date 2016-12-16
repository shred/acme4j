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

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeRateLimitExceededException}.
 */
public class AcmeRateLimitExceededExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeRateLimitExceededException() {
        String type = "urn:ietf:params:acme:error:rateLimited";
        String detail = "Too many requests per minute";
        Date retryAfter = new Date(System.currentTimeMillis() + 60 * 1000L);
        Collection<URI> documents = Arrays.asList(
                        URI.create("http://example.com/doc1.html"),
                        URI.create("http://example.com/doc2.html"));

        AcmeRateLimitExceededException ex
                = new AcmeRateLimitExceededException(type, detail, retryAfter, documents);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getRetryAfter(), is(retryAfter));
        assertThat(ex.getDocuments(), containsInAnyOrder(documents.toArray()));
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeRateLimitExceededException() {
        String type = "urn:ietf:params:acme:error:rateLimited";
        String detail = "Too many requests per minute";

        AcmeRateLimitExceededException ex
                = new AcmeRateLimitExceededException(type, detail, null, null);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getRetryAfter(), nullValue());
        assertThat(ex.getDocuments(), nullValue());
    }

}
