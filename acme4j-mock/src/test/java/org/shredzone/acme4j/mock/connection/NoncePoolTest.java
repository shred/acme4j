/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit tests for {@link NoncePool}.
 */
public class NoncePoolTest {

    /**
     * Test nonce generation.
     */
    @Test
    public void testGeneration() {
        NoncePool pool = new NoncePool();

        String nonce1 = pool.generateNonce();
        String nonce2 = pool.generateNonce();

        assertThat(nonce1, not(emptyOrNullString()));
        assertThat(nonce2, not(emptyOrNullString()));
        assertThat(nonce1, not(nonce2));
        assertThat(pool.isValidNonce(nonce1), is(true));
        assertThat(pool.isValidNonce(nonce2), is(true));
    }

    /**
     * Test nonce consumption.
     */
    @Test
    public void testConsumption() {
        NoncePool pool = new NoncePool();

        String nonce = pool.generateNonce();

        assertThat(nonce, not(emptyOrNullString()));
        assertThat(pool.isValidNonce(nonce), is(true));

        // First consumption must be valid
        boolean valid = pool.consumeNonce(nonce);
        assertThat(valid, is(true));
        assertThat(pool.isValidNonce(nonce), is(false));

        // Second consumption must fail
        boolean valid2 = pool.consumeNonce(nonce);
        assertThat(valid2, is(false));
        assertThat(pool.isValidNonce(nonce), is(false));
    }

    /**
     * Test handling of bad nonces.
     */
    @Test
    public void testBadNonce() {
        NoncePool pool = new NoncePool();

        assertThat(pool.isValidNonce("BaD-NoNcE"), is(false));
        assertThat(pool.consumeNonce("BaD-NoNcE"), is(false));
    }

}
