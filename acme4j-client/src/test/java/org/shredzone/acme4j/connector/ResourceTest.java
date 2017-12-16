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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit test for {@link Resource}.
 */
public class ResourceTest {

    /**
     * Test {@link Resource#path()}.
     */
    @Test
    public void testPath() {
        assertThat(Resource.NEW_NONCE.path(), is("newNonce"));
        assertThat(Resource.NEW_ACCOUNT.path(), is("newAccount"));
        assertThat(Resource.NEW_ORDER.path(), is("newOrder"));
        assertThat(Resource.NEW_AUTHZ.path(), is("newAuthz"));
        assertThat(Resource.REVOKE_CERT.path(), is("revokeCert"));
        assertThat(Resource.KEY_CHANGE.path(), is("keyChange"));

        // fails if there are untested future Resource values
        assertThat(Resource.values().length, is(6));
    }

}
