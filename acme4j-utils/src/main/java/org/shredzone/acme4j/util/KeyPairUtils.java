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
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Utility class offering convenience methods for {@link KeyPair}.
 * <p>
 * Requires {@code Bouncy Castle}. This class is part of the {@code acme4j-utils} module.
 */
public class KeyPairUtils {

    private KeyPairUtils() {
        // utility class without constructor
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
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
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
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
        try (PEMParser parser = new PEMParser(r)) {
            PEMKeyPair keyPair = (PEMKeyPair) parser.readObject();
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
        try (JcaPEMWriter jw = new JcaPEMWriter(w)) {
            jw.writeObject(keypair);
        }
    }

}
