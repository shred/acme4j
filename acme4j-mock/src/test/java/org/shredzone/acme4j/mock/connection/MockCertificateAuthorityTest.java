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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link MockCertificateAuthority}
 */
public class MockCertificateAuthorityTest {

    /**
     * Test that getters return valid values.
     */
    @Test
    public void testConstructor() throws Exception {
        MockCertificateAuthority ca = new MockCertificateAuthority();

        PublicKey rootKey = ca.getRootPublicKey();
        PublicKey intermediateKey = ca.getIntermediatePublicKey();
        assertThat(rootKey, not(nullValue()));
        assertThat(intermediateKey, not(nullValue()));
        assertThat(rootKey.getEncoded(), not(intermediateKey.getEncoded()));

        X509Certificate rootCert = ca.getRootCertificate();
        X509Certificate intermediateCert = ca.getIntermediateCertificate();
        assertThat(rootCert, not(nullValue()));
        assertThat(intermediateCert, not(nullValue()));

        rootCert.verify(rootKey); // root cert is self-signed
        intermediateCert.verify(rootKey); // intermediate is signed by root
    }

    /**
     * Test {@link MockCertificateAuthority#signCertificate(byte[], Instant, Instant)} and
     * {@link MockCertificateAuthority#chain(X509Certificate)}.
     */
    @Test
    public void testSignCertificate() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        Instant notBefore = Instant.now().minus(3, ChronoUnit.HOURS);
        Instant notAfter = notBefore.plus(30, ChronoUnit.DAYS);

        CSRBuilder csrBuilder = new CSRBuilder();
        csrBuilder.addDomain("example.org");
        csrBuilder.sign(keyPair);

        MockCertificateAuthority ca = new MockCertificateAuthority();

        X509Certificate cert = ca.signCertificate(csrBuilder.getEncoded(), notBefore, notAfter);
        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotBefore(), is(Date.from(notBefore.truncatedTo(ChronoUnit.SECONDS))));
        assertThat(cert.getNotAfter(), is(Date.from(notAfter.truncatedTo(ChronoUnit.SECONDS))));
        cert.verify(ca.getIntermediatePublicKey());

        List<X509Certificate> chain = ca.chain(cert);
        assertThat(chain.size(), is(3));
        assertThat(chain.get(0), sameInstance(cert));
        assertThat(chain.get(1), sameInstance(ca.getIntermediateCertificate()));
        assertThat(chain.get(2), sameInstance(ca.getRootCertificate()));
    }

    /**
     * Test {@link MockCertificateAuthority#assertValidCertificate(X509Certificate)}.
     */
    @Test
    public void testVerifyCertificate() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        CSRBuilder csrBuilder = new CSRBuilder();
        csrBuilder.addDomain("example.org");
        csrBuilder.sign(keyPair);
        byte[] csr = csrBuilder.getEncoded();

        MockCertificateAuthority ca1 = new MockCertificateAuthority();
        X509Certificate cert1 = ca1.signCertificate(csr, null, null);

        MockCertificateAuthority ca2 = new MockCertificateAuthority();
        X509Certificate cert2 = ca2.signCertificate(csr, null, null);

        // CAs accept their issued certificates
        ca1.assertValidCertificate(cert1);
        ca2.assertValidCertificate(cert2);

        // CAs mutually reject the other's certificates
        try {
            ca1.assertValidCertificate(cert2);
            fail("ca1 accepted cert2");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            ca2.assertValidCertificate(cert1);
            fail("ca2 accepted cert1");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

}