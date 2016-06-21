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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Utility class for signatures.
 *
 * @author Richard "Shred" Körber
 */
public final class SignatureUtils {

    private SignatureUtils() {
        // Utility class without constructor
    }

    /**
     * Analyzes the key used in the {@link JsonWebKey}, and returns the key algorithm
     * identifier for {@link JsonWebSignature}.
     *
     * @param jwk
     *            {@link JsonWebKey} to analyze
     * @return algorithm identifier
     * @throws IllegalArgumentException
     *             there is no corresponding algorithm identifier for the key
     */
    public static String keyAlgorithm(JsonWebKey jwk) {
        if (jwk instanceof EllipticCurveJsonWebKey) {
            EllipticCurveJsonWebKey ecjwk = (EllipticCurveJsonWebKey) jwk;

            switch (ecjwk.getCurveName()) {
                case "P-256":
                    return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;

                case "P-384":
                    return AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;

                case "P-521":
                    return AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;

                default:
                    throw new IllegalArgumentException("Unknown EC name "
                        + ecjwk.getCurveName());
            }

        } else if (jwk instanceof RsaJsonWebKey) {
            return AlgorithmIdentifiers.RSA_USING_SHA256;

        } else {
            throw new IllegalArgumentException("Unknown algorithm " + jwk.getAlgorithm());
        }
    }

    /**
     * Computes a JWK Thumbprint. It is frequently used in responses.
     *
     * @param key
     *            {@link PublicKey} to create a thumbprint of
     * @return Thumbprint, SHA-256 hashed
     * @see <a href="https://tools.ietf.org/html/rfc7638">RFC 7638</a>
     */
    public static byte[] jwkThumbprint(PublicKey key) {
        if (key == null) {
            throw new NullPointerException("key must not be null");
        }

        try {
            final JsonWebKey jwk = JsonWebKey.Factory.newJwk(key);

            // We need to use ClaimBuilder to bring the keys in lexicographical order.
            ClaimBuilder cb = new ClaimBuilder();
            cb.putAll(jwk.toParams(OutputControlLevel.PUBLIC_ONLY));

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(cb.toString().getBytes("UTF-8"));
            return md.digest();
        } catch (JoseException | NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new AcmeProtocolException("Cannot compute key thumbprint", ex);
        }
    }

}
