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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.shredzone.acme4j.challenge.TlsSniChallenge;

/**
 * Utility class offering convenience methods for certificates.
 * <p>
 * Requires {@code Bouncy Castle}.
 *
 * @author Richard "Shred" Körber
 */
public final class CertificateUtils {

    private CertificateUtils() {
        // utility class without constructor
    }

    /**
     * Reads an {@link X509Certificate} PEM file from an {@link InputStream}.
     *
     * @param in
     *            {@link InputStream} to read the certificate from.
     * @return {@link X509Certificate} that was read
     */
    public static X509Certificate readX509Certificate(InputStream in) throws IOException {
        try (InputStream uin = in) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(uin);
        } catch (CertificateException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Writes an X.509 certificate PEM file.
     *
     * @param cert
     *            {@link X509Certificate} to write
     * @param out
     *            {@link OutputStream} to write the PEM file to
     */
    public static void writeX509Certificate(X509Certificate cert, OutputStream out) throws IOException {
        writeX509Certificate(cert, new OutputStreamWriter(out, "utf-8"));
    }

    /**
     * Writes an X.509 certificate PEM file.
     *
     * @param cert
     *            {@link X509Certificate} to write
     * @param w
     *            {@link Writer} to write the PEM file to
     */
    public static void writeX509Certificate(X509Certificate cert, Writer w) throws IOException {
        try (JcaPEMWriter jw = new JcaPEMWriter(w)) {
            jw.writeObject(cert);
        }
    }

    /**
     * Creates a self-signed {@link X509Certificate} that can be used for
     * {@link TlsSniChallenge}. The certificate is valid for 7 days.
     *
     * @param keypair
     *            A domain {@link KeyPair} to be used for the challenge
     * @param subject
     *            Subject to create a certificate for
     * @return Created certificate
     */
    public static X509Certificate createTlsSniCertificate(KeyPair keypair, String subject) throws IOException {
        final long now = System.currentTimeMillis();
        final long validSpanMs = 7 * 24 * 60 * 60 * 1000L;
        final String signatureAlg = "SHA256withRSA";

        try {
            X500Name issuer = new X500Name("CN=acme.invalid");
            BigInteger serial = BigInteger.valueOf(now);
            Date notBefore = new Date(now);
            Date notAfter = new Date(now + validSpanMs);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                        issuer, serial, notBefore, notAfter, issuer, keypair.getPublic());

            GeneralName[] gns = new GeneralName[1];
            gns[0] = new GeneralName(GeneralName.dNSName, subject);

            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(gns));

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlg);

            byte[] cert = certBuilder.build(signerBuilder.build(keypair.getPrivate())).getEncoded();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
        } catch (CertificateException | OperatorCreationException ex) {
            throw new IOException(ex);
        }
    }

}
