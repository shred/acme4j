/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.junit.Test;

/**
 * Tests of {@link EmailIdentifier}.
 */
public class EmailIdentifierTest {

    @Test
    public void testConstants() {
        assertThat(EmailIdentifier.TYPE_EMAIL, is("email"));
    }

    @Test
    public void testEmail() throws AddressException {
        EmailIdentifier id1 = EmailIdentifier.email("email@example.com");
        assertThat(id1.getType(), is(EmailIdentifier.TYPE_EMAIL));
        assertThat(id1.getValue(), is("email@example.com"));
        assertThat(id1.getEmailAddress().getAddress(), is("email@example.com"));

        EmailIdentifier id2 = EmailIdentifier.email(new InternetAddress("email@example.com"));
        assertThat(id2.getType(), is(EmailIdentifier.TYPE_EMAIL));
        assertThat(id2.getValue(), is("email@example.com"));
        assertThat(id2.getEmailAddress().getAddress(), is("email@example.com"));

        EmailIdentifier id3 = EmailIdentifier.email(new InternetAddress("Example Corp <info@example.com>"));
        assertThat(id3.getType(), is(EmailIdentifier.TYPE_EMAIL));
        assertThat(id3.getValue(), is("info@example.com"));
        assertThat(id3.getEmailAddress().getAddress(), is("info@example.com"));
    }

}