/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.wrapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyStoreException;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SignedMailBuilder}.
 */
public class SignedMailBuilderTest {

    @Test
    public void testDefaultTrustStoreIsCreated() throws KeyStoreException {
        var keyStore = SignedMailBuilder.getCaCertsTrustStore();
        assertThat(keyStore).isNotNull();
        assertThat(keyStore.size()).isGreaterThan(0);

        // Make sure the instance is cached
        var keyStore2 = SignedMailBuilder.getCaCertsTrustStore();
        assertThat(keyStore2).isSameAs(keyStore);
    }

}