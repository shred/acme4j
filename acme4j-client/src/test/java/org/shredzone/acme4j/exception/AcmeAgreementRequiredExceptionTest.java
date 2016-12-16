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

import org.junit.Test;

/**
 * Unit tests for {@link AcmeAgreementRequiredException}.
 */
public class AcmeAgreementRequiredExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeAgreementRequiredException() {
        String type = "urn:ietf:params:acme:error:agreementRequired";
        String detail = "Agreement is required";
        URI agreementUri = URI.create("http://example.com/agreement.pdf");
        URI instanceUri = URI.create("http://example.com/howToAgree.html");

        AcmeAgreementRequiredException ex
            = new AcmeAgreementRequiredException(type, detail, agreementUri, instanceUri);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getAgreementUri(), is(agreementUri));
        assertThat(ex.getInstance(), is(instanceUri));
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeAgreementRequiredException() {
        String type = "urn:ietf:params:acme:error:agreementRequired";
        String detail = "Agreement is required";

        AcmeAgreementRequiredException ex
            = new AcmeAgreementRequiredException(type, detail, null, null);

        assertThat(ex.getType(), is(type));
        assertThat(ex.getMessage(), is(detail));
        assertThat(ex.getAgreementUri(), nullValue());
        assertThat(ex.getInstance(), nullValue());
    }

}
