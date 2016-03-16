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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.challenge.ProofOfPossession01Challenge;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Generates a validation string for {@link ProofOfPossession01Challenge}.
 *
 * @author Richard "Shred" Körber
 */
public class ValidationBuilder {

    private final List<Map<String, Object>> identifiers = new ArrayList<>();

    /**
     * Adds a domain to the validation.
     *
     * @param domain
     *            Domain to be added
     * @return {@code this}
     */
    public ValidationBuilder domain(String domain) {
        if (domain == null || domain.isEmpty()) {
            throw new IllegalArgumentException("domain must not be empty or null");
        }

        ClaimBuilder cb = new ClaimBuilder();
        cb.put("type", "dns").put("value", domain);
        identifiers.add(cb.toMap());
        return this;
    }

    /**
     * Adds a collection of domains to the validation.
     *
     * @param domains
     *            Domains to be added
     * @return {@code this}
     */
    public ValidationBuilder domains(Collection<String> domains) {
        if (domains == null) {
            throw new NullPointerException("domains must not be null");
        }

        for (String d : domains) {
            domain(d);
        }
        return this;
    }

    /**
     * Adds multiple domains to the validation.
     *
     * @param domains
     *            Domains to be added
     * @return {@code this}
     */
    public ValidationBuilder domains(String... domains) {
        return domains(Arrays.asList(domains));
    }

    /**
     * Signs with the given {@link KeyPair} and returns a signed JSON Web Signature
     * structure that can be used for validation.
     *
     * @param registration
     *            {@link Registration} of the current domain owner
     * @param keypair
     *            One of the {@link KeyPair} requested by the challenge
     * @return JWS validation object
     */
    public String sign(Registration registration, KeyPair keypair) {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (keypair == null) {
            throw new NullPointerException("keypair must not be null");
        }

        try {
            ClaimBuilder claims = new ClaimBuilder();
            claims.put("type", ProofOfPossession01Challenge.TYPE);
            claims.array("identifiers", identifiers.toArray());
            claims.putKey("accountKey", registration.getKeyPair().getPublic());

            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(keypair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toString());
            jws.getHeaders().setJwkHeaderValue("jwk", jwk);
            jws.setAlgorithmHeaderValue(SignatureUtils.keyAlgorithm(jwk));
            jws.setKey(keypair.getPrivate());
            jws.sign();

            ClaimBuilder auth = new ClaimBuilder();
            auth.put("header", jws.getHeaders().getFullHeaderAsJsonString());
            auth.put("payload", jws.getEncodedPayload());
            auth.put("signature", jws.getEncodedSignature());
            return auth.toString();
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Failed to sign", ex);
        }
    }

}
