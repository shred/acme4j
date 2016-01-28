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
package org.shredzone.acme4j.challenge;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.ValidationBuilder;

/**
 * Implements the {@code proof-of-possession-01} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class ProofOfPossessionChallenge extends GenericChallenge {
    private static final long serialVersionUID = 6212440828380185335L;

    protected static final String KEY_CERTS = "certs";
    protected static final String KEY_AUTHORIZATION = "authorization";

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "proof-of-possession-01";

    private Collection<X509Certificate> certs;
    private String validation;

    /**
     * Gets the collection of {@link X509Certificate} known by the server.
     */
    public Collection<X509Certificate> getCertificates() {
        return certs;
    }

    /**
     * Authorizes the challenge by signing it with the {@link Registration} of the current
     * domain owner.
     *
     * @param ownerRegistration
     *            {@link Registration} of the certificate holder
     * @param domainKeypair
     *            {@link KeyPair} matching one of the requested certificates
     * @param domains
     *            Domains to validate
     */
    public void authorize(Registration ownerRegistration, KeyPair domainKeypair, String... domains) {
        importValidation(new ValidationBuilder()
                .domains(domains)
                .sign(ownerRegistration, domainKeypair));
    }

    /**
     * Imports a validation JWS.
     *
     * @param validation
     *            JWS of the validation
     * @see ValidationBuilder
     */
   public void importValidation(String validation) {
        try {
            Map<String, Object> json = JsonUtil.parseJson(validation);
            if (!json.keySet().containsAll(Arrays.asList("header", "payload", "signature"))) {
                throw new IllegalArgumentException("not a JWS");
            }
        } catch (JoseException ex) {
            throw new IllegalArgumentException("invalid JSON", ex);
        }

        this.validation = validation;
    }

    @Override
    public void unmarshall(Map<String, Object> map) {
        super.unmarshall(map);

        List<String> certData = get(KEY_CERTS);
        if (certData != null) {
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

                certs = new ArrayList<>(certData.size());
                for (String c : certData) {
                    byte[] certDer = Base64Url.decode(c);
                    try (ByteArrayInputStream in = new ByteArrayInputStream(certDer)) {
                        certs.add((X509Certificate) certificateFactory.generateCertificate(in));
                    }
                }
            } catch (CertificateException | IOException ex) {
                throw new IllegalArgumentException("Invalid certs", ex);
            }
        }
    }

    @Override
    public void respond(ClaimBuilder cb) {
        if (validation == null) {
            throw new IllegalStateException("not validated");
        }

        super.respond(cb);

        try {
            cb.put(KEY_AUTHORIZATION, JsonUtil.parseJson(validation));
        } catch (JoseException ex) {
            // should not happen, as the JSON is prevalidated in the setter
            throw new IllegalStateException("validation: invalid JSON", ex);
        }
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
