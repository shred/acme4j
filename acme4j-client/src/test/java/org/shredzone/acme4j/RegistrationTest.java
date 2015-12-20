/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;

/**
 * Unit tests for {@link Registration}.
 *
 * @author Richard "Shred" Körber
 */
public class RegistrationTest {

    /**
     * Test getters and setters.
     */
    @Test
    public void testGetterAndSetter() throws URISyntaxException {
        Registration registration = new Registration();

        assertThat(registration.getAgreement(), is(nullValue()));
        assertThat(registration.getLocation(), is(nullValue()));
        assertThat(registration.getContacts(), is(empty()));

        registration.setAgreement(new URI("http://example.com/agreement.pdf"));
        registration.setLocation(new URI("http://example.com/acme/12345"));
        registration.getContacts().add("mailto:foo@example.com");
        registration.getContacts().add("mailto:bar@example.com");

        assertThat(registration.getAgreement(), is(new URI("http://example.com/agreement.pdf")));
        assertThat(registration.getLocation(), is(new URI("http://example.com/acme/12345")));
        assertThat(registration.getContacts(), contains("mailto:foo@example.com", "mailto:bar@example.com"));
    }

    /**
     * Test constructors;
     */
    @Test
    public void testConstructor() throws URISyntaxException {
        Registration registration1 = new Registration();
        assertThat(registration1.getLocation(), is(nullValue()));

        Registration registration2 = new Registration(new URI("http://example.com/acme/12345"));
        assertThat(registration2.getLocation(), is(new URI("http://example.com/acme/12345")));
    }

}
