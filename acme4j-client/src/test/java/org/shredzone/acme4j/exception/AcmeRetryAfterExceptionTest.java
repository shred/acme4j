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

import java.util.Date;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeRetryAfterException}.
 */
public class AcmeRetryAfterExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeRetryAfterException() {
        String detail = "Too early";
        Date retryAfter = new Date(System.currentTimeMillis() + 60 * 1000L);

        AcmeRetryAfterException ex
                = new AcmeRetryAfterException(detail, retryAfter);

        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getRetryAfter(), is(retryAfter));

        // make sure we get a copy of the Date object
        assertThat(ex.getRetryAfter(), not(sameInstance(retryAfter)));
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeRetryAfterException() {
        Date retryAfter = new Date(System.currentTimeMillis() + 60 * 1000L);

        AcmeRetryAfterException ex
                = new AcmeRetryAfterException(null, retryAfter);

        assertThat(ex.getMessage(), nullValue());
        assertThat(ex.getRetryAfter(), is(retryAfter));

        // make sure we get a copy of the Date object
        assertThat(ex.getRetryAfter(), not(sameInstance(retryAfter)));
    }

    /**
     * Test that date is required.
     */
    @Test(expected = NullPointerException.class)
    public void testRequiredAcmeRetryAfterException() {
        new AcmeRetryAfterException("null-test", null);
    }

}
