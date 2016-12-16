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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.net.URI;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeConflictException}.
 */
public class AcmeConflictExceptionTest {

    @Test
    public void testAcmeConflictException() {
        String msg = "Account already exists";
        URI locationUri = URI.create("http://example.com/location/123");

        AcmeConflictException ex
            = new AcmeConflictException(msg, locationUri);

        assertThat(ex.getMessage(), is(msg));
        assertThat(ex.getLocation(), is(locationUri));
    }

}
