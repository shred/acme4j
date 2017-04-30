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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeUserActionRequiredException}.
 */
public class AcmeUserActionRequiredExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeUserActionRequiredException() throws MalformedURLException {
        String type = "urn:ietf:params:acme:error:userActionRequired";
        String detail = "Accept new TOS";
        URI tosUri = URI.create("http://example.com/agreement.pdf");
        URL instanceUrl = new URL("http://example.com/howToAgree.html");

        AcmeUserActionRequiredException ex
            = new AcmeUserActionRequiredException(type, detail, tosUri, instanceUrl);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getTermsOfServiceUri(), is(tosUri));
        assertThat(ex.getInstance(), is(instanceUrl));
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeUserActionRequiredException() {
        String type = "urn:ietf:params:acme:error:userActionRequired";
        String detail = "Call our service";

        AcmeUserActionRequiredException ex
            = new AcmeUserActionRequiredException(type, detail, null, null);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getTermsOfServiceUri(), nullValue());
        assertThat(ex.getInstance(), nullValue());
    }

}
