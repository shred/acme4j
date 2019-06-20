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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * A mock certificate authority. It has a random root certificate and intermediate
 * certificate, and is able to create signed certificates based on CSRs.
 * <p>
 * The CA's root and intermediate certificates are valid for 30 days. The signed
 * certificates are valid for 7 days. This should be more than sufficient for unit
 * testing.
 * <p>
 * This is a very simple implementation that is for testing purposes only. Do not use this
 * code to run your own CA.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockCertificateAuthority {
    private KeyPair rootKeyPair;
    private KeyPair intermediateKeyPair;
    private X509Certificate rootCertificate;
    private X509Certificate intermediateCertificate;

    /**
     * Lazily set up the CA.
     */
    private void setup() {
        if (rootKeyPair == null) {
            Instant notBefore = Instant.now();
            Instant notAfter = notBefore.plus(Duration.ofDays(30));

            rootKeyPair = KeyPairUtils.createKeyPair(2048);
            rootCertificate = CertificateUtils.createTestRootCertificate(
                    "CN=Mock Root Certificate",
                    notBefore,
                    notAfter,
                    rootKeyPair
            );

            intermediateKeyPair = KeyPairUtils.createKeyPair(2048);
            intermediateCertificate = CertificateUtils.createTestIntermediateCertificate(
                    "CN=Mock Intermediate Certificate",
                    notBefore,
                    notAfter,
                    intermediateKeyPair.getPublic(),
                    getRootCertificate(),
                    rootKeyPair.getPrivate()
            );
        }
    }

    /**
     * Creates and signs a certificate based on the given CSR.
     *
     * @param csr
     *         Certificate Signing Request
     * @param notBefore
     *         Certificate is valid starting from that instant. If {@code null}, the
     *         certificate is valid starting now.
     * @param notAfter
     *         Certificate is valid until that instant. If {@code null}, it is valid for 7
     *         days starting from {@code notBefore}.
     * @return The signed {@link X509Certificate}. It is valid for 7 days.
     */
    public X509Certificate signCertificate(byte[] csr, @Nullable Instant notBefore,
            @Nullable Instant notAfter) {
        setup();
        try {
            Instant nb = notBefore != null ? notBefore : Instant.now();
            Instant na = notAfter != null ? notAfter : nb.plus(Duration.ofDays(7));

            if (!na.isAfter(nb)) {
                throw new IllegalArgumentException("ending date is before starting date");
            }

            return CertificateUtils.createTestCertificate(
                    new PKCS10CertificationRequest(csr),
                    nb,
                    na,
                    intermediateCertificate,
                    intermediateKeyPair.getPrivate()
            );
        } catch (IOException ex) {
            throw new IllegalArgumentException("Could not read CSR", ex);
        }
    }

    /**
     * Returns a certificate chain for the given certificate.
     *
     * @param cert
     *         End entity certificate
     * @return Chain containing the end entity certificate, the intermediate certificate,
     * and the root certificate.
     * @throws IllegalArgumentException
     *         The given end entity certificate was not issued by this {@link
     *         MockCertificateAuthority} instance.
     */
    public List<X509Certificate> chain(X509Certificate cert) {
        assertValidCertificate(cert);
        return Arrays.asList(cert, intermediateCertificate, rootCertificate);
    }

    /**
     * Asserts that the given end entity certificate was issued by this {@link
     * MockCertificateAuthority} instance.
     *
     * @param cert
     *         {@link X509Certificate} to check
     * @throws IllegalArgumentException
     *         The given end entity certificate was not issued by this {@link
     *         MockCertificateAuthority} instance.
     */
    public void assertValidCertificate(X509Certificate cert) {
        try {
            cert.verify(getIntermediatePublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchProviderException | SignatureException ex) {
            throw new IllegalArgumentException("Bad certificate", ex);
        }
    }

    /**
     * Returns the CA's root certificate.
     */
    public X509Certificate getRootCertificate() {
        setup();
        return rootCertificate;
    }

    /**
     * Returns the CA's intermediate certificate.
     */
    public X509Certificate getIntermediateCertificate() {
        setup();
        return intermediateCertificate;
    }

    /**
     * Returns the CA's root public key.
     */
    public PublicKey getRootPublicKey() {
        setup();
        return rootKeyPair.getPublic();
    }

    /**
     * Returns the CA's intermediate public key.
     */
    public PublicKey getIntermediatePublicKey() {
        setup();
        return intermediateKeyPair.getPublic();
    }

}
