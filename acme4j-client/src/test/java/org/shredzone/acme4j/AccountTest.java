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
import java.security.KeyPair;

import org.junit.Test;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Account}.
 *
 * @author Richard "Shred" Körber
 */
public class AccountTest {

    /**
     * Test getters and setters.
     */
    @Test
    public void testGetterAndSetter() throws IOException {
        KeyPair keypair = TestUtils.createKeyPair();

        Account account = new Account(keypair);

        assertThat(account.getKeyPair(), is(sameInstance(keypair)));
    }

    /**
     * Test null values.
     */
    @Test(expected = NullPointerException.class)
    public void testNull() {
        new Account(null);
    }

}
