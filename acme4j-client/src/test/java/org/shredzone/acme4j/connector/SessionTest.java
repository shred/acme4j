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
package org.shredzone.acme4j.connector;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit test for {@link Session}.
 *
 * @author Richard "Shred" Körber
 */
public class SessionTest {

    /**
     * Test getters and setters.
     */
    @Test
    public void testGettersAndSetters() {
        Session session = new Session();

        assertThat(session.getNonce(), is(nullValue()));

        byte[] data = "foo-nonce-bar".getBytes();

        session.setNonce(data);
        assertThat(session.getNonce(), is(equalTo(data)));
    }

}
