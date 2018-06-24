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
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.security.KeyPair;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
import org.shredzone.acme4j.toolbox.AcmeUtils;

/**
 * Unit tests for {@link CertificateUtils}.
 */
public class CertificateUtilsTest {

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
     * Test if
     * {@link CertificateUtils#createTlsAlpn01Certificate(KeyPair, String, byte[])}
     * creates a good certificate.
     */
    @Test
    public void testCreateTlsAlpn01Certificate() throws IOException, CertificateParsingException {
        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        String subject = "example.com";
        byte[] acmeValidationV1 = AcmeUtils.sha256hash("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ");

        X509Certificate cert = CertificateUtils.createTlsAlpn01Certificate(keypair, subject, acmeValidationV1);

        Instant now = Instant.now();
        Instant end = now.plus(Duration.ofDays(8));

        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), is(greaterThan(Date.from(now))));
        assertThat(cert.getNotAfter(), is(lessThan(Date.from(end))));
        assertThat(cert.getNotBefore(), is(lessThanOrEqualTo(Date.from(now))));

        assertThat(cert.getSubjectX500Principal().getName(), is("CN=acme.invalid"));
        assertThat(getSANs(cert), contains(subject));

        assertThat(cert.getCriticalExtensionOIDs(), hasItem(TlsAlpn01Challenge.ACME_VALIDATION_V1_OID));

        byte[] encodedExtensionValue = cert.getExtensionValue(TlsAlpn01Challenge.ACME_VALIDATION_V1_OID);
        assertThat(encodedExtensionValue, is(notNullValue()));

        try (ASN1InputStream asn = new ASN1InputStream(new ByteArrayInputStream(encodedExtensionValue))) {
            DEROctetString derOctetString = (DEROctetString) asn.readObject();

            byte[] test = new byte[acmeValidationV1.length + 2];
            test[0] = BERTags.OCTET_STRING;
            test[1] = (byte) acmeValidationV1.length;
            System.arraycopy(acmeValidationV1, 0, test, 2, acmeValidationV1.length);

            assertThat(derOctetString.getOctets(), is(test));
        }
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
