/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import static org.shredzone.acme4j.toolbox.AcmeUtils.sha256hash;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.util.CertificateUtils;

/**
 * Implements the {@value TYPE} challenge. It requires a specific certificate that can be
 * retrieved from the domain via HTTPS request. See the acme4j documentation for a
 * detailed explanation.
 *
 * @since 2.1
 */
public class TlsAlpn01Challenge extends TokenChallenge {
    private static final long serialVersionUID = -5590351078176091228L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-alpn-01";

    /**
     * OID of the {@code acmeValidation} extension.
     */
    public static final String ACME_VALIDATION_OID = "1.3.6.1.5.5.7.1.31";

    /**
     * {@code acme-tls/1} protocol.
     */
    public static final String ACME_TLS_1_PROTOCOL = "acme-tls/1";

    /**
     * Creates a new generic {@link TlsAlpn01Challenge} object.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param data
     *            {@link JSON} challenge data
     */
    public TlsAlpn01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Returns the value that is to be used as {@code acmeValidation} extension in
     * the test certificate.
     */
    public byte[] getAcmeValidation() {
        return sha256hash(getAuthorization());
    }

    /**
     * Creates a self-signed {@link X509Certificate} for this challenge. The certificate
     * is valid for 7 days.
     *
     * @param keypair
     *         A domain {@link KeyPair} to be used for the challenge
     * @param id
     *         The {@link Identifier} that is to be validated
     * @return Created certificate
     * @since 3.0.0
     */
    public X509Certificate createCertificate(KeyPair keypair, Identifier id) {
        try {
            return CertificateUtils.createTlsAlpn01Certificate(keypair, id, getAcmeValidation());
        } catch (IOException ex) {
            throw new IllegalArgumentException("Bad certificate parameters", ex);
        }
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
