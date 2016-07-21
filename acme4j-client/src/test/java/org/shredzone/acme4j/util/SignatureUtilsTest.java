/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link SignatureUtils}.
 */
public class SignatureUtilsTest {

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test if RSA using SHA-256 keys are properly detected.
     */
    @Test
    public void testRsaKey() throws Exception {
        KeyPair rsaKeyPair = TestUtils.createKeyPair();
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(rsaKeyPair.getPublic());

        String type = SignatureUtils.keyAlgorithm(jwk);

        assertThat(type, is("RS256"));
    }

    /**
     * Test if ECDSA using NIST P-256 curve and SHA-256 keys are properly detected.
     */
    @Test
    public void testP256ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp256r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = SignatureUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES256"));
    }

    /**
     * Test if ECDSA using NIST P-384 curve and SHA-384 keys are properly detected.
     */
    @Test
    public void testP384ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp384r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = SignatureUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES384"));
    }

    /**
     * Test if ECDSA using NIST P-521 curve and SHA-512 keys are properly detected.
     */
    @Test
    public void testP521ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp521r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = SignatureUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES512"));
    }

    /**
     * Test if {@link SignatureUtils#jwkThumbprint(java.security.PublicKey)} returns the
     * correct thumb print.
     */
    @Test
    public void testJwkThumbprint() throws Exception {
        KeyPair keyPair = TestUtils.createKeyPair();

        byte[] thumbprint = SignatureUtils.jwkThumbprint(keyPair.getPublic());

        assertThat(Base64Url.encode(thumbprint), is(TestUtils.THUMBPRINT));
    }

}
