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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeException}.
 */
public class AcmeExceptionTest {

    @Test
    public void testAcmeException() {
        AcmeException ex = new AcmeException();
        assertThat(ex.getMessage(), nullValue());
        assertThat(ex.getCause(), nullValue());
    }

    @Test
    public void testMessageAcmeException() {
        String message = "Failure";
        AcmeException ex = new AcmeException(message);
        assertThat(ex.getMessage(), is(message));
        assertThat(ex.getCause(), nullValue());
    }

    @Test
    public void testCausedAcmeException() {
        String message = "Failure";
        IOException cause = new IOException("No network");

        AcmeException ex = new AcmeException(message, cause);
        assertThat(ex.getMessage(), is(message));
        assertThat(ex.getCause(), is((Throwable) cause));
    }

}
