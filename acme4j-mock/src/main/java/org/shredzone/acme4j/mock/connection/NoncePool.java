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

import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.ThreadSafe;

import org.shredzone.acme4j.toolbox.AcmeUtils;

/**
 * A nonce pool. This class is thread safe.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
@ThreadSafe
public class NoncePool {
    private static final Random RND = new Random();

    private final Set<String> nonces = new TreeSet<>();

    /**
     * Generates a new random nonce.
     *
     * @return New nonce
     */
    public String generateNonce() {
        String newNonce;
        synchronized (this) {
            byte[] data = new byte[16];
            do {
                RND.nextBytes(data);
                newNonce = AcmeUtils.base64UrlEncode(data);
            } while (nonces.contains(newNonce));
            nonces.add(newNonce);
        }
        return newNonce;
    }

    /**
     * Tests if the given nonce is valid, without consuming it.
     *
     * @param nonce
     *         Nonce to test
     * @return {@code true} if it is a valid nonce that was issued by this pool and has
     * not been used yet.
     */
    public boolean isValidNonce(String nonce) {
        synchronized (this) {
            return nonces.contains(nonce);
        }
    }

    /**
     * Consumes the nonce. The nonce must have been issued by this {@link NoncePool}, and
     * must not have been used yet.
     *
     * @param nonce
     *         Nonce to consume
     * @return {@code true} if the nonce was issued by this pool, and was not used yet.
     * {@code false} if the nonce is unknown or was already consumed.
     */
    public boolean consumeNonce(String nonce) {
        synchronized (this) {
            return nonces.remove(nonce);
        }
    }

}
