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

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Utility class offering convenience methods for {@link KeyPair}.
 * <p>
 * Requires {@code Bouncy Castle}.
 */
public class KeyPairUtils {

    private KeyPairUtils() {
        // utility class without constructor
    }

    /**
     * Creates a new standard {@link KeyPair}.
     * <p>
     * This method can be used if no specific key type is required. It returns a
     * "secp384r1" ECDSA key pair.
     *
     * @return Generated {@link KeyPair}
     * @since 2.8
     */
    public static KeyPair createKeyPair() {
        return createECKeyPair("secp384r1");
    }

    /**
     * Creates a new RSA {@link KeyPair}.
     *
     * @param keysize
     *            Key size
     * @return Generated {@link KeyPair}
     */
    public static KeyPair createKeyPair(int keysize) {
        try {
            var keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keysize);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Creates a new elliptic curve {@link KeyPair}.
     *
     * @param name
     *            ECDSA curve name (e.g. "secp256r1")
     * @return Generated {@link KeyPair}
     */
    public static KeyPair createECKeyPair(String name) {
        try {
            var ecSpec = ECNamedCurveTable.getParameterSpec(name);
            var g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw new IllegalArgumentException("Invalid curve name " + name, ex);
        } catch (NoSuchProviderException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Reads a {@link KeyPair} from a PEM file.
     *
     * @param r
     *            {@link Reader} to read the PEM file from. The {@link Reader} is closed
     *            after use.
     * @return {@link KeyPair} read
     */
    public static KeyPair readKeyPair(Reader r) throws IOException {
        try (var parser = new PEMParser(r)) {
            var keyPair = (PEMKeyPair) parser.readObject();
            return new JcaPEMKeyConverter().getKeyPair(keyPair);
        } catch (PEMException ex) {
            throw new IOException("Invalid PEM file", ex);
        }
    }

    /**
     * Writes a {@link KeyPair} PEM file.
     *
     * @param keypair
     *            {@link KeyPair} to write
     * @param w
     *            {@link Writer} to write the PEM file to. The {@link Writer} is closed
     *            after use.
     */
    public static void writeKeyPair(KeyPair keypair, Writer w) throws IOException {
        try (var jw = new JcaPEMWriter(w)) {
            jw.writeObject(keypair);
        }
    }

    /**
     * Writes a {@link PublicKey} as PEM file.
     *
     * @param key
     *            {@link PublicKey}
     * @param w
     *            {@link Writer} to write the PEM file to. The {@link Writer} is closed
     *            after use.
     * @since 3.0.0
     */
    public static void writePublicKey(PublicKey key, Writer w) throws IOException {
        try (var jw = new JcaPEMWriter(w)) {
            jw.writeObject(key);
        }
    }

}
