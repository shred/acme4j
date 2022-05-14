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

import static org.assertj.core.api.Assertions.assertThat;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;

/**
 * Unit test for {@link Resource}.
 */
public class ResourceTest {

    /**
     * Test {@link Resource#path()}.
     */
    @Test
    public void testPath() {
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(Resource.NEW_NONCE.path()).isEqualTo("newNonce");
            softly.assertThat(Resource.NEW_ACCOUNT.path()).isEqualTo("newAccount");
            softly.assertThat(Resource.NEW_ORDER.path()).isEqualTo("newOrder");
            softly.assertThat(Resource.NEW_AUTHZ.path()).isEqualTo("newAuthz");
            softly.assertThat(Resource.REVOKE_CERT.path()).isEqualTo("revokeCert");
            softly.assertThat(Resource.KEY_CHANGE.path()).isEqualTo("keyChange");
        });

        // fails if there are untested future Resource values
        assertThat(Resource.values()).hasSize(6);
    }

}
