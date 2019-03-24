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
package org.shredzone.acme4j.toolbox;

import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.crypto.SecretKey;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class that takes care of all the JOSE stuff.
 *
 * @since 2.7
 */
@ParametersAreNonnullByDefault
public final class JoseUtils {

    private static final Logger LOG = LoggerFactory.getLogger(JoseUtils.class);

    private JoseUtils() {
        // Utility class without constructor
    }

    /**
     * Creates an ACME JOSE request.
     *
     * @param url
     *         {@link URL} of the ACME call
     * @param keypair
     *         {@link KeyPair} to sign the request with
     * @param payload
     *         ACME JSON payload. If {@code null}, a POST-as-GET request is generated
     *         instead.
     * @param nonce
     *         Nonce to be used. {@code null} if no nonce is to be used in the JOSE
     *         header.
     * @param kid
     *         kid to be used in the JOSE header. If {@code null}, a jwk header of the
     *         given key is used instead.
     * @return JSON structure of the JOSE request, ready to be sent.
     */
    public static JSONBuilder createJoseRequest(URL url, KeyPair keypair,
            @Nullable JSONBuilder payload, @Nullable String nonce, @Nullable String kid) {
        try {
            PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.getHeaders().setObjectHeaderValue("url", url);

            if (kid != null) {
                jws.getHeaders().setObjectHeaderValue("kid", kid);
            } else {
                jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            }

            if (nonce != null) {
                jws.getHeaders().setObjectHeaderValue("nonce", nonce);
            }

            jws.setPayload(payload != null ? payload.toString() : "");
            jws.setAlgorithmHeaderValue(keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            jws.sign();

            if (LOG.isDebugEnabled()) {
                LOG.debug("{} {}", payload != null ? "POST" : "POST-as-GET", url);
                if (payload != null) {
                    LOG.debug("  Payload: {}", payload);
                }
                LOG.debug("  JWS Header: {}", jws.getHeaders().getFullHeaderAsJsonString());
            }

            JSONBuilder jb = new JSONBuilder();
            jb.put("protected", jws.getHeaders().getEncodedHeader());
            jb.put("payload", jws.getEncodedPayload());
            jb.put("signature", jws.getEncodedSignature());
            return jb;
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to sign a JSON request", ex);
        }
    }

    /**
     * Creates a JSON structure for external account binding.
     *
     * @param kid
     *         Key Identifier provided by the CA
     * @param accountKey
     *         {@link PublicKey} of the account to register
     * @param macKey
     *         {@link SecretKey} to sign the key identifier with
     * @param resource
     *         "newAccount" resource URL
     * @return Created JSON structure
     */
    public static Map<String, Object> createExternalAccountBinding(String kid,
            PublicKey accountKey, SecretKey macKey, URL resource) throws AcmeException {
        try {
            PublicJsonWebKey keyJwk = PublicJsonWebKey.Factory.newPublicJwk(accountKey);

            JsonWebSignature innerJws = new JsonWebSignature();
            innerJws.setPayload(keyJwk.toJson());
            innerJws.getHeaders().setObjectHeaderValue("url", resource);
            innerJws.getHeaders().setObjectHeaderValue("kid", kid);
            innerJws.setAlgorithmHeaderValue(macKeyAlgorithm(macKey));
            innerJws.setKey(macKey);
            innerJws.setDoKeyValidation(false);
            innerJws.sign();

            JSONBuilder outerClaim = new JSONBuilder();
            outerClaim.put("protected", innerJws.getHeaders().getEncodedHeader());
            outerClaim.put("signature", innerJws.getEncodedSignature());
            outerClaim.put("payload", innerJws.getEncodedPayload());
            return outerClaim.toMap();
        } catch (JoseException ex) {
            throw new AcmeException("Could not create external account binding", ex);
        }
    }

    /**
     * Converts a {@link PublicKey} to a JOSE JWK structure.
     *
     * @param key
     *         {@link PublicKey} to convert
     * @return JSON map containing the JWK structure
     */
    public static Map<String, Object> publicKeyToJWK(PublicKey key) {
        try {
            return PublicJsonWebKey.Factory.newPublicJwk(key)
                    .toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        } catch (JoseException ex) {
            throw new IllegalArgumentException("Bad public key", ex);
        }
    }

    /**
     * Computes a thumbprint of the given public key.
     *
     * @param key
     *         {@link PublicKey} to get the thumbprint of
     * @return Thumbprint of the key
     */
    public static byte[] thumbprint(PublicKey key) {
        try {
            PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(key);
            return jwk.calculateThumbprint("SHA-256");
        } catch (JoseException ex) {
            throw new IllegalArgumentException("Bad public key", ex);
        }
    }

    /**
     * Analyzes the key used in the {@link JsonWebKey}, and returns the key algorithm
     * identifier for {@link JsonWebSignature}.
     *
     * @param jwk
     *         {@link JsonWebKey} to analyze
     * @return algorithm identifier
     * @throws IllegalArgumentException
     *         there is no corresponding algorithm identifier for the key
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
     * Analyzes the {@link SecretKey}, and returns the key algorithm identifier for {@link
     * JsonWebSignature}.
     *
     * @param macKey
     *         {@link SecretKey} to analyze
     * @return algorithm identifier
     * @throws IllegalArgumentException
     *         there is no corresponding algorithm identifier for the key
     */
    public static String macKeyAlgorithm(SecretKey macKey) {
        if (!"HMAC".equals(macKey.getAlgorithm())) {
            throw new IllegalArgumentException("Bad algorithm: " + macKey.getAlgorithm());
        }

        int size = macKey.getEncoded().length * 8;
        switch (size) {
            case 256:
                return AlgorithmIdentifiers.HMAC_SHA256;

            case 384:
                return AlgorithmIdentifiers.HMAC_SHA384;

            case 512:
                return AlgorithmIdentifiers.HMAC_SHA512;

            default:
                throw new IllegalArgumentException("Bad key size: " + size);
        }
    }

}
