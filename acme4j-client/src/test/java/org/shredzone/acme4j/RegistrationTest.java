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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;

import org.junit.Test;
import org.shredzone.acme4j.util.TestUtils;

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
    public void testGetterAndSetter() throws IOException, URISyntaxException {
        KeyPair keypair = TestUtils.createKeyPair();
        Registration registration = new Registration(keypair);

        assertThat(registration.getAgreement(), is(nullValue()));
        assertThat(registration.getLocation(), is(nullValue()));
        assertThat(registration.getContacts(), is(empty()));
        assertThat(registration.getKeyPair(), is(sameInstance(keypair)));

        registration.setAgreement(new URI("http://example.com/agreement.pdf"));
        registration.setLocation(new URI("http://example.com/acme/12345"));
        registration.getContacts().add(new URI("mailto:foo@example.com"));
        registration.addContact(new URI("tel:+1-212-555-0101"));
        registration.addContact("mailto:foo2@example.com");

        assertThat(registration.getAgreement(), is(new URI("http://example.com/agreement.pdf")));
        assertThat(registration.getLocation(), is(new URI("http://example.com/acme/12345")));
        assertThat(registration.getContacts(), contains(
                        new URI("mailto:foo@example.com"), new URI("tel:+1-212-555-0101"),
                        new URI("mailto:foo2@example.com")));
    }

    /**
     * Test constructors.
     */
    @Test
    public void testConstructor() throws IOException, URISyntaxException {
        KeyPair keypair = TestUtils.createKeyPair();

        Registration registration1 = new Registration(keypair);
        assertThat(registration1.getLocation(), is(nullValue()));
        assertThat(registration1.getKeyPair(), is(sameInstance(keypair)));

        Registration registration2 = new Registration(keypair, new URI("http://example.com/acme/12345"));
        assertThat(registration2.getLocation(), is(new URI("http://example.com/acme/12345")));
        assertThat(registration2.getKeyPair(), is(sameInstance(keypair)));
    }

}
