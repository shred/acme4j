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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

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

}
