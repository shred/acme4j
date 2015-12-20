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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Before;
import org.junit.Test;

import com.jcabi.matchers.RegexMatchers;

/**
 * Unit tests for {@link CertificateUtils}.
 *
 * @author Richard "Shred" Körber
 */
public class CertificateUtilsTest {

    private CertificateFactory certificateFactory;

    @Before
    public void setup() throws CertificateException {
        certificateFactory = CertificateFactory.getInstance("X.509");
    }

    /**
     * Test if {@link CertificateUtils#readX509Certificate(InputStream)} reads and
     * {@link CertificateUtils#writeX509Certificate(X509Certificate, java.io.Writer)}
     * writes a proper X.509 certificate.
     */
    @Test
    public void testReadWriteX509Certificate() throws IOException, CertificateException {
        // Read a demonstration certificate
        X509Certificate original;
        try (InputStream cert = getClass().getResourceAsStream("/cert.pem")) {
            original = (X509Certificate) certificateFactory.generateCertificate(cert);
        }
        assertThat(original, is(notNullValue()));

        // Write to StringWriter
        byte[] pem;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            CertificateUtils.writeX509Certificate(original, out);
            pem = out.toByteArray();
        }

        // Make sure it is a good PEM file
        assertThat(new String(pem, "utf-8"), RegexMatchers.matchesPattern(
                        "-----BEGIN CERTIFICATE-----[\\r\\n]+"
                      + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                      + "-----END CERTIFICATE-----[\\r\\n]*"));

        // Read it back in
        X509Certificate written = CertificateUtils.readX509Certificate(new ByteArrayInputStream(pem));

        // Verify that both certificates are the same
        assertThat(original.getEncoded(), is(equalTo(written.getEncoded())));
    }

}
