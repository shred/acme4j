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
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;

import com.jcabi.matchers.RegexMatchers;

/**
 * Unit tests for {@link CertificateUtils}.
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
        X509Certificate original = createCertificate();

        // Write to Byte Array
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

    /**
     * Test if
     * {@link CertificateUtils#writeX509CertificateChain(java.io.Writer, X509Certificate, X509Certificate...)}
     * writes a correct chain.
     */
    @Test
    public void testWriteX509CertificateChain() throws IOException, CertificateException {
        X509Certificate leaf = createCertificate();
        X509Certificate chain1 = createCertificate();
        X509Certificate chain2 = createCertificate();

        String out;
        try (StringWriter w = new StringWriter()) {
            CertificateUtils.writeX509CertificateChain(w, leaf);
            out = w.toString();
        }
        assertThat(countCertificates(out), is(1));

        try (StringWriter w = new StringWriter()) {
            CertificateUtils.writeX509CertificateChain(w, leaf, chain1);
            out = w.toString();
        }
        assertThat(countCertificates(out), is(2));

        try (StringWriter w = new StringWriter()) {
            CertificateUtils.writeX509CertificateChain(w, leaf, chain1, chain2);
            out = w.toString();
        }
        assertThat(countCertificates(out), is(3));

        try (StringWriter w = new StringWriter()) {
            CertificateUtils.writeX509CertificateChain(w, leaf, chain1, null, chain2);
            out = w.toString();
        }
        assertThat(countCertificates(out), is(3));
    }

    /**
     * Test if {@link CertificateUtils#createTlsSniCertificate(KeyPair, String)} creates a
     * good certificate.
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testCreateTlsSniCertificate() throws IOException, CertificateParsingException {
        String subject = "30c452b9bd088cdbc2c4094947025d7c.7364ea602ac325a1b55ceaae024fbe29.acme.invalid";

        KeyPair keypair = KeyPairUtils.createKeyPair(2048);

        X509Certificate cert = CertificateUtils.createTlsSniCertificate(keypair, subject);

        Instant now = Instant.now();
        Instant end = now.plus(Duration.ofDays(8));

        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), is(greaterThan(Date.from(now))));
        assertThat(cert.getNotAfter(), is(lessThan(Date.from(end))));
        assertThat(cert.getNotBefore(), is(lessThanOrEqualTo(Date.from(now))));
        assertThat(cert.getSubjectX500Principal().getName(), is("CN=acme.invalid"));
        assertThat(getSANs(cert), containsInAnyOrder(subject));
    }

    /**
     * Test if {@link CertificateUtils#createTlsSni02Certificate(KeyPair, String, String)}
     * creates a good certificate.
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testCreateTlsSni02Certificate() throws IOException, CertificateParsingException {
        String sanA = "1082909237a535173c8415a44539f84e.248317530d8d1a0c71de8fd23f1beae4.token.acme.invalid";
        String sanB = "edc3a1d40199c1723358d57853bc23ff.4d4473417a6d76e80df17bbcfbe53d2c.ka.acme.invalid";

        KeyPair keypair = KeyPairUtils.createKeyPair(2048);

        X509Certificate cert = CertificateUtils.createTlsSni02Certificate(keypair, sanA, sanB);

        Instant now = Instant.now();
        Instant end = now.plus(Duration.ofDays(8));

        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), is(greaterThan(Date.from(now))));
        assertThat(cert.getNotAfter(), is(lessThan(Date.from(end))));
        assertThat(cert.getNotBefore(), is(lessThanOrEqualTo(Date.from(now))));
        assertThat(cert.getSubjectX500Principal().getName(), is("CN=acme.invalid"));
        assertThat(getSANs(cert), containsInAnyOrder(sanA, sanB));
    }

    /**
     * Test if {@link CertificateUtils#readCSR(InputStream)} reads an identical CSR.
     */
    @Test
    public void testReadCSR() throws IOException {
        KeyPair keypair = KeyPairUtils.createKeyPair(2048);

        CSRBuilder builder = new CSRBuilder();
        builder.addDomains("example.com", "example.org");
        builder.sign(keypair);

        PKCS10CertificationRequest original = builder.getCSR();
        byte[] pemFile;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemFile = baos.toByteArray();
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(pemFile)) {
            PKCS10CertificationRequest read = CertificateUtils.readCSR(bais);
            assertThat(original.getEncoded(), is(equalTo(read.getEncoded())));
        }
    }

    /**
     * Returns a test certificates.
     */
    private X509Certificate createCertificate() throws IOException, CertificateException {
        X509Certificate original;
        try (InputStream cert = getClass().getResourceAsStream("/cert.pem")) {
            original = (X509Certificate) certificateFactory.generateCertificate(cert);
        }
        assertThat(original, is(notNullValue()));
        return original;
    }

    /**
     * Test that constructor is private.
     */
    @Test
    public void testPrivateConstructor() throws Exception {
        Constructor<CertificateUtils> constructor = CertificateUtils.class.getDeclaredConstructor();
        assertThat(Modifier.isPrivate(constructor.getModifiers()), is(true));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    /**
     * Counts number of certificates in a PEM string.
     *
     * @param str
     *            String containing certificates in PEM format
     * @return Number of certificates found
     */
    private int countCertificates(String str) {
        int count = 0;
        int pos = 0;
        while (true) {
            pos = str.indexOf("-----BEGIN CERTIFICATE-----", pos);
            if (pos < 0) break;
            count++;
            pos++;
        }
        return count;
    }

    /**
     * Extracts all DNSName SANs from a certificate.
     *
     * @param cert
     *            {@link X509Certificate}
     * @return Set of DNSName
     */
    private Set<String> getSANs(X509Certificate cert) throws CertificateParsingException {
        Set<String> result = new HashSet<>();

        for (List<?> list : cert.getSubjectAlternativeNames()) {
            if (((Number) list.get(0)).intValue() == GeneralName.dNSName) {
                result.add((String) list.get(1));
            }
        }

        return result;
    }

}
