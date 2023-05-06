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
import static org.shredzone.acme4j.toolbox.TestUtils.createProblem;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AcmeUserActionRequiredException}.
 */
public class AcmeUserActionRequiredExceptionTest {

    /**
     * Test that parameters are correctly returned.
     */
    @Test
    public void testAcmeUserActionRequiredException() throws MalformedURLException {
        var type = URI.create("urn:ietf:params:acme:error:userActionRequired");
        var detail = "Accept new TOS";
        var tosUri = URI.create("http://example.com/agreement.pdf");
        var instanceUrl = new URL("http://example.com/howToAgree.html");

        var problem = createProblem(type, detail, instanceUrl);

        var ex = new AcmeUserActionRequiredException(problem, tosUri);

        assertThat(ex.getType()).isEqualTo(type);
        assertThat(ex.getMessage()).isEqualTo(detail);
        assertThat(ex.getTermsOfServiceUri().orElseThrow()).isEqualTo(tosUri);
        assertThat(ex.getInstance()).isEqualTo(instanceUrl);
    }

    /**
     * Test that optional parameters are null-safe.
     */
    @Test
    public void testNullAcmeUserActionRequiredException() throws MalformedURLException {
        var type = URI.create("urn:ietf:params:acme:error:userActionRequired");
        var detail = "Call our service";
        var instanceUrl = new URL("http://example.com/howToContactUs.html");

        var problem = createProblem(type, detail, instanceUrl);

        var ex = new AcmeUserActionRequiredException(problem, null);

        assertThat(ex.getType()).isEqualTo(type);
        assertThat(ex.getMessage()).isEqualTo(detail);
        assertThat(ex.getTermsOfServiceUri()).isEmpty();
        assertThat(ex.getInstance()).isEqualTo(instanceUrl);
    }

}
