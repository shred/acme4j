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

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import org.shredzone.acme4j.Identifier;
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
     * {@link CertificateUtils#createTlsAlpn01Certificate(KeyPair, Identifier, byte[])}
     * with domain name creates a good certificate.
     */
    @Test
    public void testCreateTlsAlpn01Certificate() throws IOException, CertificateParsingException {
        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        String subject = "example.com";
        byte[] acmeValidationV1 = AcmeUtils.sha256hash("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ");

        X509Certificate cert = CertificateUtils.createTlsAlpn01Certificate(keypair, Identifier.dns(subject), acmeValidationV1);

        Instant now = Instant.now();
        Instant end = now.plus(Duration.ofDays(8));

        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), is(greaterThan(Date.from(now))));
        assertThat(cert.getNotAfter(), is(lessThan(Date.from(end))));
        assertThat(cert.getNotBefore(), is(lessThanOrEqualTo(Date.from(now))));

        assertThat(cert.getSubjectX500Principal().getName(), is("CN=acme.invalid"));
        assertThat(getSANs(cert), contains(subject));

        assertThat(cert.getCriticalExtensionOIDs(), hasItem(TlsAlpn01Challenge.ACME_VALIDATION_OID));

        byte[] encodedExtensionValue = cert.getExtensionValue(TlsAlpn01Challenge.ACME_VALIDATION_OID);
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
     * Test if
     * {@link CertificateUtils#createTlsAlpn01Certificate(KeyPair, Identifier, byte[])}
     * with IP creates a good certificate.
     */
    @Test
    public void testCreateTlsAlpn01CertificateWithIp() throws IOException, CertificateParsingException {
        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        InetAddress subject = InetAddress.getLocalHost();
        byte[] acmeValidationV1 = AcmeUtils.sha256hash("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ");

        X509Certificate cert = CertificateUtils.createTlsAlpn01Certificate(keypair, Identifier.ip(subject), acmeValidationV1);

        assertThat(cert.getSubjectX500Principal().getName(), is("CN=acme.invalid"));
        assertThat(getIpSANs(cert), contains(subject));
    }

    /**
     * Test if {@link CertificateUtils#createTestRootCertificate(String, Instant, Instant,
     * KeyPair)} generates a valid root certificate.
     */
    @Test
    public void testCreateTestRootCertificate() throws Exception {
        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        String subject = "CN=Test Root Certificate";
        Instant notBefore = Instant.now().truncatedTo(SECONDS);
        Instant notAfter = notBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        X509Certificate cert = CertificateUtils.createTestRootCertificate(subject,
                notBefore, notAfter, keypair);

        assertThat(cert.getIssuerX500Principal().getName(), is(subject));
        assertThat(cert.getSubjectX500Principal().getName(), is(subject));
        assertThat(cert.getNotBefore().toInstant(), is(notBefore));
        assertThat(cert.getNotAfter().toInstant(), is(notAfter));
        assertThat(cert.getSerialNumber(), not(nullValue()));
        assertThat(cert.getPublicKey(), is(keypair.getPublic()));
        cert.verify(cert.getPublicKey()); // self-signed
    }

    /**
     * Test if {@link CertificateUtils#createTestIntermediateCertificate(String, Instant,
     * Instant, PublicKey, X509Certificate, PrivateKey)} generates a valid intermediate
     * certificate.
     */
    @Test
    public void testCreateTestIntermediateCertificate() throws Exception {
        KeyPair rootKeypair = KeyPairUtils.createKeyPair(2048);
        String rootSubject = "CN=Test Root Certificate";
        Instant rootNotBefore = Instant.now().minus(Duration.ofDays(1)).truncatedTo(SECONDS);
        Instant rootNotAfter = rootNotBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        X509Certificate rootCert = CertificateUtils.createTestRootCertificate(rootSubject,
                rootNotBefore, rootNotAfter, rootKeypair);

        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        String subject = "CN=Test Intermediate Certificate";
        Instant notBefore = Instant.now().truncatedTo(SECONDS);
        Instant notAfter = notBefore.plus(Duration.ofDays(7)).truncatedTo(SECONDS);

        X509Certificate cert = CertificateUtils.createTestIntermediateCertificate(subject,
                notBefore, notAfter, keypair.getPublic(), rootCert, rootKeypair.getPrivate());

        assertThat(cert.getIssuerX500Principal().getName(), is(rootSubject));
        assertThat(cert.getSubjectX500Principal().getName(), is(subject));
        assertThat(cert.getNotBefore().toInstant(), is(notBefore));
        assertThat(cert.getNotAfter().toInstant(), is(notAfter));
        assertThat(cert.getSerialNumber(), not(nullValue()));
        assertThat(cert.getSerialNumber(), not(rootCert.getSerialNumber()));
        assertThat(cert.getPublicKey(), is(keypair.getPublic()));
        cert.verify(rootKeypair.getPublic()); // signed by root
    }

    /**
     * Test if {@link CertificateUtils#createTestCertificate(PKCS10CertificationRequest,
     * Instant, Instant, X509Certificate, PrivateKey)} generates a valid certificate.
     */
    @Test
    public void testCreateTestCertificate() throws Exception {
        KeyPair rootKeypair = KeyPairUtils.createKeyPair(2048);
        String rootSubject = "CN=Test Root Certificate";
        Instant rootNotBefore = Instant.now().minus(Duration.ofDays(1)).truncatedTo(SECONDS);
        Instant rootNotAfter = rootNotBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        X509Certificate rootCert = CertificateUtils.createTestRootCertificate(rootSubject,
                rootNotBefore, rootNotAfter, rootKeypair);

        KeyPair keypair = KeyPairUtils.createKeyPair(2048);
        Instant notBefore = Instant.now().truncatedTo(SECONDS);
        Instant notAfter = notBefore.plus(Duration.ofDays(7)).truncatedTo(SECONDS);

        CSRBuilder builder = new CSRBuilder();
        builder.addDomains("example.org", "www.example.org");
        builder.addIP(InetAddress.getByName("192.168.0.1"));
        builder.sign(keypair);
        PKCS10CertificationRequest csr = builder.getCSR();

        X509Certificate cert = CertificateUtils.createTestCertificate(csr, notBefore,
                notAfter, rootCert, rootKeypair.getPrivate());

        assertThat(cert.getIssuerX500Principal().getName(), is(rootSubject));
        assertThat(cert.getSubjectX500Principal().getName(), is("CN=example.org"));
        assertThat(getSANs(cert), contains("example.org", "www.example.org"));
        assertThat(getIpSANs(cert), contains(InetAddress.getByName("192.168.0.1")));
        assertThat(cert.getNotBefore().toInstant(), is(notBefore));
        assertThat(cert.getNotAfter().toInstant(), is(notAfter));
        assertThat(cert.getSerialNumber(), not(nullValue()));
        assertThat(cert.getSerialNumber(), not(rootCert.getSerialNumber()));
        assertThat(cert.getPublicKey(), is(keypair.getPublic()));
        cert.verify(rootKeypair.getPublic()); // signed by root
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

    /**
     * Extracts all IPAddress SANs from a certificate.
     *
     * @param cert
     *            {@link X509Certificate}
     * @return Set of IPAddresses
     */
    private Set<InetAddress> getIpSANs(X509Certificate cert) throws CertificateParsingException, UnknownHostException {
        Set<InetAddress> result = new HashSet<>();

        for (List<?> list : cert.getSubjectAlternativeNames()) {
            if (((Number) list.get(0)).intValue() == GeneralName.iPAddress) {
                result.add(InetAddress.getByName(list.get(1).toString()));
            }
        }

        return result;
    }

}
