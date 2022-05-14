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
import static org.hamcrest.Matchers.*;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AcmeProtocolException}.
 */
public class AcmeProtocolExceptionTest {

    @Test
    public void testAcmeProtocolException() {
        String msg = "Bad content";
        AcmeProtocolException ex = new AcmeProtocolException(msg);
        assertThat(ex, is(instanceOf(RuntimeException.class)));
        assertThat(ex.getMessage(), is(msg));
        assertThat(ex.getCause(), nullValue());
    }

    @Test
    public void testCausedAcmeProtocolException() {
        String message = "Bad content";
        NumberFormatException cause = new NumberFormatException("Not a number: abc");
        AcmeProtocolException ex = new AcmeProtocolException(message, cause);
        assertThat(ex.getMessage(), is(message));
        assertThat(ex.getCause(), is(cause));
    }

}
