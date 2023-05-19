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
import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
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
        var keypair = KeyPairUtils.createKeyPair(2048);

        var builder = new CSRBuilder();
        builder.addDomains("example.com", "example.org");
        builder.sign(keypair);

        var original = builder.getCSR();
        byte[] pemFile;
        try (var baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemFile = baos.toByteArray();
        }

        try (var bais = new ByteArrayInputStream(pemFile)) {
            var read = CertificateUtils.readCSR(bais);
            assertThat(original.getEncoded()).isEqualTo(read.getEncoded());
        }
    }

    /**
     * Test that constructor is private.
     */
    @Test
    public void testPrivateConstructor() throws Exception {
        var constructor = CertificateUtils.class.getDeclaredConstructor();
        assertThat(Modifier.isPrivate(constructor.getModifiers())).isTrue();
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    /**
     * Test if
     * {@link CertificateUtils#createTlsAlpn01Certificate(KeyPair, Identifier, byte[])}
     * with domain name creates a good certificate.
     */
    @Test
    public void testCreateTlsAlpn01Certificate() throws Exception {
        var keypair = KeyPairUtils.createKeyPair(2048);
        var subject = "example.com";
        var acmeValidationV1 = AcmeUtils.sha256hash("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ");

        var cert = CertificateUtils.createTlsAlpn01Certificate(keypair, Identifier.dns(subject), acmeValidationV1);

        var now = Instant.now();
        var end = now.plus(Duration.ofDays(8));

        assertThat(cert).isNotNull();
        assertThat(cert.getNotAfter()).isAfter(Date.from(now));
        assertThat(cert.getNotAfter()).isBefore(Date.from(end));
        assertThat(cert.getNotBefore()).isBeforeOrEqualTo(Date.from(now));

        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=acme.invalid");
        assertThat(getSANs(cert)).contains(subject);

        assertThat(cert.getCriticalExtensionOIDs()).contains(TlsAlpn01Challenge.ACME_VALIDATION_OID);

        var encodedExtensionValue = cert.getExtensionValue(TlsAlpn01Challenge.ACME_VALIDATION_OID);
        assertThat(encodedExtensionValue).isNotNull();

        try (var asn = new ASN1InputStream(new ByteArrayInputStream(encodedExtensionValue))) {
            var derOctetString = (DEROctetString) asn.readObject();

            var test = new byte[acmeValidationV1.length + 2];
            test[0] = BERTags.OCTET_STRING;
            test[1] = (byte) acmeValidationV1.length;
            System.arraycopy(acmeValidationV1, 0, test, 2, acmeValidationV1.length);

            assertThat(derOctetString.getOctets()).isEqualTo(test);
        }

        cert.verify(keypair.getPublic());
    }

    /**
     * Test if
     * {@link CertificateUtils#createTlsAlpn01Certificate(KeyPair, Identifier, byte[])}
     * with IP creates a good certificate.
     */
    @Test
    public void testCreateTlsAlpn01CertificateWithIp() throws IOException, CertificateParsingException {
        var keypair = KeyPairUtils.createKeyPair(2048);
        var subject = InetAddress.getLocalHost();
        var acmeValidationV1 = AcmeUtils.sha256hash("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ");

        var cert = CertificateUtils.createTlsAlpn01Certificate(keypair, Identifier.ip(subject), acmeValidationV1);

        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=acme.invalid");
        assertThat(getIpSANs(cert)).contains(subject);
    }

    /**
     * Test if {@link CertificateUtils#createTestRootCertificate(String, Instant, Instant,
     * KeyPair)} generates a valid root certificate.
     */
    @Test
    public void testCreateTestRootCertificate() throws Exception {
        var keypair = KeyPairUtils.createKeyPair(2048);
        var subject = "CN=Test Root Certificate";
        var notBefore = Instant.now().truncatedTo(SECONDS);
        var notAfter = notBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        var cert = CertificateUtils.createTestRootCertificate(subject,
                notBefore, notAfter, keypair);

        assertThat(cert.getIssuerX500Principal().getName()).isEqualTo(subject);
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo(subject);
        assertThat(cert.getNotBefore().toInstant()).isEqualTo(notBefore);
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(notAfter);
        assertThat(cert.getSerialNumber()).isNotNull();
        assertThat(cert.getPublicKey()).isEqualTo(keypair.getPublic());
        cert.verify(cert.getPublicKey()); // self-signed
    }

    /**
     * Test if {@link CertificateUtils#createTestIntermediateCertificate(String, Instant,
     * Instant, PublicKey, X509Certificate, PrivateKey)} generates a valid intermediate
     * certificate.
     */
    @Test
    public void testCreateTestIntermediateCertificate() throws Exception {
        var rootKeypair = KeyPairUtils.createKeyPair(2048);
        var rootSubject = "CN=Test Root Certificate";
        var rootNotBefore = Instant.now().minus(Duration.ofDays(1)).truncatedTo(SECONDS);
        var rootNotAfter = rootNotBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        var rootCert = CertificateUtils.createTestRootCertificate(rootSubject,
                rootNotBefore, rootNotAfter, rootKeypair);

        var keypair = KeyPairUtils.createKeyPair(2048);
        var subject = "CN=Test Intermediate Certificate";
        var notBefore = Instant.now().truncatedTo(SECONDS);
        var notAfter = notBefore.plus(Duration.ofDays(7)).truncatedTo(SECONDS);

        var cert = CertificateUtils.createTestIntermediateCertificate(subject,
                notBefore, notAfter, keypair.getPublic(), rootCert, rootKeypair.getPrivate());

        assertThat(cert.getIssuerX500Principal().getName()).isEqualTo(rootSubject);
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo(subject);
        assertThat(cert.getNotBefore().toInstant()).isEqualTo(notBefore);
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(notAfter);
        assertThat(cert.getSerialNumber()).isNotNull();
        assertThat(cert.getSerialNumber()).isNotEqualTo(rootCert.getSerialNumber());
        assertThat(cert.getPublicKey()).isEqualTo(keypair.getPublic());
        cert.verify(rootKeypair.getPublic()); // signed by root
    }

    /**
     * Test if {@link CertificateUtils#createTestCertificate(PKCS10CertificationRequest,
     * Instant, Instant, X509Certificate, PrivateKey)} generates a valid certificate.
     */
    @Test
    public void testCreateTestCertificate() throws Exception {
        var rootKeypair = KeyPairUtils.createKeyPair(2048);
        var rootSubject = "CN=Test Root Certificate";
        var rootNotBefore = Instant.now().minus(Duration.ofDays(1)).truncatedTo(SECONDS);
        var rootNotAfter = rootNotBefore.plus(Duration.ofDays(14)).truncatedTo(SECONDS);

        var rootCert = CertificateUtils.createTestRootCertificate(rootSubject,
                rootNotBefore, rootNotAfter, rootKeypair);

        var keypair = KeyPairUtils.createKeyPair(2048);
        var notBefore = Instant.now().truncatedTo(SECONDS);
        var notAfter = notBefore.plus(Duration.ofDays(7)).truncatedTo(SECONDS);

        var builder = new CSRBuilder();
        builder.addDomains("example.org", "www.example.org");
        builder.addIP(InetAddress.getByName("192.168.0.1"));
        builder.sign(keypair);
        var csr = builder.getCSR();

        var cert = CertificateUtils.createTestCertificate(csr, notBefore,
                notAfter, rootCert, rootKeypair.getPrivate());

        assertThat(cert.getIssuerX500Principal().getName()).isEqualTo(rootSubject);
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=example.org");
        assertThat(getSANs(cert)).contains("example.org", "www.example.org");
        assertThat(getIpSANs(cert)).contains(InetAddress.getByName("192.168.0.1"));
        assertThat(cert.getNotBefore().toInstant()).isEqualTo(notBefore);
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(notAfter);
        assertThat(cert.getSerialNumber()).isNotNull();
        assertThat(cert.getSerialNumber()).isNotEqualTo(rootCert.getSerialNumber());
        assertThat(cert.getPublicKey()).isEqualTo(keypair.getPublic());
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
        var result = new HashSet<String>();

        for (var list : cert.getSubjectAlternativeNames()) {
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
        var result = new HashSet<InetAddress>();

        for (var list : cert.getSubjectAlternativeNames()) {
            if (((Number) list.get(0)).intValue() == GeneralName.iPAddress) {
                result.add(InetAddress.getByName(list.get(1).toString()));
            }
        }

        return result;
    }

}
