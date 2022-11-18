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
import static org.mockito.Mockito.mock;

import java.net.URL;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AcmeLazyLoadingException}.
 */
public class AcmeLazyLoadingExceptionTest {

    private final URL resourceUrl = TestUtils.url("http://example.com/acme/resource/123");

    @Test
    public void testAcmeLazyLoadingException() {
        var login = mock(Login.class);
        var resource = new TestResource(login, resourceUrl);

        var cause = new AcmeException("Something went wrong");

        var ex = new AcmeLazyLoadingException(resource, cause);
        assertThat(ex).isInstanceOf(RuntimeException.class);
        assertThat(ex.getMessage()).contains(resourceUrl.toString());
        assertThat(ex.getMessage()).contains(TestResource.class.getSimpleName());
        assertThat(ex.getCause()).isEqualTo(cause);
        assertThat(ex.getType()).isEqualTo(TestResource.class);
        assertThat(ex.getLocation()).isEqualTo(resourceUrl);
    }

    private static class TestResource extends AcmeResource {
        private static final long serialVersionUID = 1023419539450677538L;

        public TestResource(Login login, URL location) {
            super(login, location);
        }
    }

}
