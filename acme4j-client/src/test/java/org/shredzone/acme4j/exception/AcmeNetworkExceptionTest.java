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

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AcmeNetworkException}.
 */
public class AcmeNetworkExceptionTest {

    @Test
    public void testAcmeNetworkException() {
        var cause = new IOException("Network not reachable");

        var ex = new AcmeNetworkException(cause);

        assertThat(ex.getMessage()).isNotNull();
        assertThat(ex.getCause()).isEqualTo(cause);
    }

}
