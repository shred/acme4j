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
import static org.mockito.Mockito.mock;

import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AcmeLazyLoadingException}.
 */
public class AcmeLazyLoadingExceptionTest {

    private URL resourceUrl = TestUtils.url("http://example.com/acme/resource/123");

    @Test
    public void testAcmeLazyLoadingException() {
        Login login = mock(Login.class);
        AcmeResource resource = new TestResource(login, resourceUrl);

        AcmeException cause = new AcmeException("Something went wrong");

        AcmeLazyLoadingException ex = new AcmeLazyLoadingException(resource, cause);
        assertThat(ex, is(instanceOf(RuntimeException.class)));
        assertThat(ex.getMessage(), containsString(resourceUrl.toString()));
        assertThat(ex.getMessage(), containsString(TestResource.class.getSimpleName()));
        assertThat(ex.getCause(), is((Throwable) cause));
        assertThat(ex.getType(), is(equalTo(TestResource.class)));
        assertThat(ex.getLocation(), is(resourceUrl));
    }

    private static class TestResource extends AcmeResource {
        private static final long serialVersionUID = 1023419539450677538L;

        public TestResource(Login login, URL location) {
            super(login, location);
        }
    }

}
