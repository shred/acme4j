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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.jcabi.matchers.RegexMatchers;

/**
 * Unit tests for {@link KeyPairUtils}.
 */
public class KeyPairUtilsTest {
    private static final int KEY_SIZE = 2048;
    private static final String EC_CURVE = "secp256r1";

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that RSA keypairs of the correct size are generated.
     */
    @Test
    public void testCreateKeyPair() {
        KeyPair pair = KeyPairUtils.createKeyPair(KEY_SIZE);
        assertThat(pair, is(notNullValue()));
        assertThat(pair.getPublic(), is(instanceOf(RSAPublicKey.class)));

        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        assertThat(pub.getModulus().bitLength(), is(KEY_SIZE));
    }

    /**
     * Test that reading and writing keypairs work correctly.
     */
    @Test
    public void testWriteAndRead() throws IOException {
        // Generate a test keypair
        KeyPair pair = KeyPairUtils.createKeyPair(KEY_SIZE);

        // Write keypair to PEM
        String pem;
        try (StringWriter out = new StringWriter()) {
            KeyPairUtils.writeKeyPair(pair, out);
            pem = out.toString();
        }

        // Make sure PEM file is properly formatted
        assertThat(pem, RegexMatchers.matchesPattern(
                  "-----BEGIN RSA PRIVATE KEY-----[\\r\\n]+"
                + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                + "-----END RSA PRIVATE KEY-----[\\r\\n]*"));

        // Read keypair from PEM
        KeyPair readPair;
        try (StringReader in = new StringReader(pem)) {
            readPair = KeyPairUtils.readKeyPair(in);
        }

        // Verify that both keypairs are the same
        assertThat(pair, not(sameInstance(readPair)));
        assertThat(pair.getPublic().getEncoded(), is(equalTo(readPair.getPublic().getEncoded())));
        assertThat(pair.getPrivate().getEncoded(), is(equalTo(readPair.getPrivate().getEncoded())));
    }

    /**
     * Test that ECDSA keypairs are generated.
     */
    @Test
    public void testCreateECCKeyPair() {
        KeyPair pair = KeyPairUtils.createECKeyPair(EC_CURVE);
        assertThat(pair, is(notNullValue()));
        assertThat(pair.getPublic(), is(instanceOf(ECPublicKey.class)));
    }

    /**
     * Test that reading and writing ECDSA keypairs work correctly.
     */
    @Test
    public void testWriteAndReadEC() throws IOException {
        // Generate a test keypair
        KeyPair pair = KeyPairUtils.createECKeyPair(EC_CURVE);

        // Write keypair to PEM
        String pem;
        try (StringWriter out = new StringWriter()) {
            KeyPairUtils.writeKeyPair(pair, out);
            pem = out.toString();
        }

        // Make sure PEM file is properly formatted
        assertThat(pem, RegexMatchers.matchesPattern(
                  "-----BEGIN EC PRIVATE KEY-----[\\r\\n]+"
                + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                + "-----END EC PRIVATE KEY-----[\\r\\n]*"));

        // Read keypair from PEM
        KeyPair readPair;
        try (StringReader in = new StringReader(pem)) {
            readPair = KeyPairUtils.readKeyPair(in);
        }

        // Verify that both keypairs are the same
        assertThat(pair, not(sameInstance(readPair)));
        assertThat(pair.getPublic().getEncoded(), is(equalTo(readPair.getPublic().getEncoded())));
        assertThat(pair.getPrivate().getEncoded(), is(equalTo(readPair.getPrivate().getEncoded())));
    }

}
