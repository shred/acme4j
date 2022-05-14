/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.csr;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link SMIMECSRBuilder}.
 */
public class SMIMECSRBuilderTest {

    private static KeyPair testKey;
    private static KeyPair testEcKey;

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());

        testKey = KeyPairUtils.createKeyPair(512);
        testEcKey = KeyPairUtils.createECKeyPair("secp256r1");
    }

    /**
     * Test if the generated S/MIME CSR is plausible.
     */
    @Test
    public void testSMIMEGenerate() throws IOException, AddressException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();
        builder.addEmail(new InternetAddress("Contact <mail@example.com>"));
        builder.addEmail(new InternetAddress("Info <info@example.com>"));
        builder.addEmails(new InternetAddress("Sales Dept <sales@example.com>"),
                new InternetAddress("shop@example.com"));
        builder.addEmails(Arrays.asList(
                new InternetAddress("support@example.com"),
                new InternetAddress("help@example.com"))
        );

        builder.setCountry("XX");
        builder.setLocality("Testville");
        builder.setOrganization("Testing Co");
        builder.setOrganizationalUnit("Testunit");
        builder.setState("ABC");

        assertThat(builder.toString()).isEqualTo("CN=mail@example.com,C=XX,L=Testville,"
                + "O=Testing Co,OU=Testunit,ST=ABC,"
                + "EMAIL=mail@example.com,EMAIL=info@example.com,"
                + "EMAIL=sales@example.com,EMAIL=shop@example.com,"
                + "EMAIL=support@example.com,EMAIL=help@example.com,"
                + "TYPE=SIGNING_AND_ENCRYPTION");

        builder.sign(testKey);

        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr).isNotNull();
        assertThat(csr.getEncoded()).isEqualTo(builder.getEncoded());

        smimeCsrTest(csr);
        keyUsageTest(csr, KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        writerTest(builder);
    }

    /**
     * Test if the generated S/MIME CSR correctly sets the encryption only flag.
     */
    @Test
    public void testSMIMEEncryptOnly() throws IOException, AddressException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();
        builder.addEmail(new InternetAddress("mail@example.com"));
        builder.setKeyUsageType(KeyUsageType.ENCRYPTION_ONLY);
        builder.sign(testKey);
        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr).isNotNull();
        keyUsageTest(csr, KeyUsage.keyEncipherment);
    }

    /**
     * Test if the generated S/MIME CSR correctly sets the signing only flag.
     */
    @Test
    public void testSMIMESigningOnly() throws IOException, AddressException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();
        builder.addEmail(new InternetAddress("mail@example.com"));
        builder.setKeyUsageType(KeyUsageType.SIGNING_ONLY);
        builder.sign(testKey);
        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr).isNotNull();
        keyUsageTest(csr, KeyUsage.digitalSignature);
    }

    /**
     * Test if the generated S/MIME CSR correctly sets the signing and encryption flag.
     */
    @Test
    public void testSMIMESigningAndEncryption() throws IOException, AddressException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();
        builder.addEmail(new InternetAddress("mail@example.com"));
        builder.setKeyUsageType(KeyUsageType.SIGNING_AND_ENCRYPTION);
        builder.sign(testKey);
        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr).isNotNull();
        keyUsageTest(csr, KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
    }

    /**
     * Checks if the S/MIME CSR contains the right parameters.
     * <p>
     * This is not supposed to be a Bouncy Castle test. If the
     * {@link PKCS10CertificationRequest} contains the right parameters, we assume that
     * Bouncy Castle encodes it properly.
     */
    private void smimeCsrTest(PKCS10CertificationRequest csr) {
        X500Name name = csr.getSubject();

        try (AutoCloseableSoftAssertions softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(name.getRDNs(BCStyle.CN)).as("CN")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("mail@example.com");
            softly.assertThat(name.getRDNs(BCStyle.C)).as("C")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("XX");
            softly.assertThat(name.getRDNs(BCStyle.L)).as("L")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("Testville");
            softly.assertThat(name.getRDNs(BCStyle.O)).as("O")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("Testing Co");
            softly.assertThat(name.getRDNs(BCStyle.OU)).as("OU")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("Testunit");
            softly.assertThat(name.getRDNs(BCStyle.ST)).as("ST")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("ABC");
        }

        Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(attr).hasSize(1);

        ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions).hasSize(1);

        GeneralNames names = GeneralNames.fromExtensions((Extensions) extensions[0], Extension.subjectAlternativeName);
        assertThat(names.getNames())
                .filteredOn(gn -> gn.getTagNo() == GeneralName.rfc822Name)
                .extracting(gn -> DERIA5String.getInstance(gn.getName()).getString())
                .containsExactlyInAnyOrder("mail@example.com", "info@example.com",
                        "sales@example.com", "shop@example.com", "support@example.com",
                        "help@example.com");
    }

    /**
     * Validate the Key Usage bits.
     *
     * @param csr
     *         {@link PKCS10CertificationRequest} to validate
     * @param expectedUsageBits
     *         Expected key usage bits. Exact match, validation fails if other bits are
     *         set or reset. If {@code null}, validation fails if key usage bits are set.
     */
    private void keyUsageTest(PKCS10CertificationRequest csr, Integer expectedUsageBits) {
        Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(attr).hasSize(1);
        ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions).hasSize(1);
        DERBitString keyUsageBits = (DERBitString) ((Extensions) extensions[0]).getExtensionParsedValue(Extension.keyUsage);
        if (expectedUsageBits != null) {
            assertThat(keyUsageBits.intValue()).isEqualTo(expectedUsageBits);
        } else {
            assertThat(keyUsageBits).isNull();
        }
    }

    /**
     * Checks if the {@link SMIMECSRBuilder#write(java.io.Writer)} method generates a
     * correct CSR PEM file.
     */
    private void writerTest(SMIMECSRBuilder builder) throws IOException {
        // Write CSR to PEM
        String pem;
        try (StringWriter out = new StringWriter()) {
            builder.write(out);
            pem = out.toString();
        }

        // Make sure PEM file is properly formatted
        assertThat(pem).matches(
                  "-----BEGIN CERTIFICATE REQUEST-----[\\r\\n]+"
                + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                + "-----END CERTIFICATE REQUEST-----[\\r\\n]*");

        // Read CSR from PEM
        PKCS10CertificationRequest readCsr;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            readCsr = (PKCS10CertificationRequest) parser.readObject();
        }

        // Verify that both keypairs are the same
        assertThat(builder.getCSR()).isNotSameAs(readCsr);
        assertThat(builder.getEncoded()).isEqualTo(readCsr.getEncoded());

        // OutputStream is identical?
        byte[] pemBytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemBytes = baos.toByteArray();
        }
        assertThat(new String(pemBytes, UTF_8)).isEqualTo(pem);
    }

    /**
     * Make sure an exception is thrown when nothing is set.
     */
    @Test
    public void testNoEmail() throws IOException {
        assertThrows(IllegalStateException.class, () -> {
            SMIMECSRBuilder builder = new SMIMECSRBuilder();
            builder.sign(testKey);
        });
    }

    /**
     * Make sure all getters will fail if the CSR is not signed.
     */
    @Test
    public void testNoSign() throws IOException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();

        assertThrows(IllegalStateException.class, builder::getCSR, "getCSR");
        assertThrows(IllegalStateException.class, builder::getEncoded, "getEncoded");
        assertThrows(IllegalStateException.class, () -> {
            try (StringWriter w = new StringWriter()) {
                builder.write(w);
            }
        },"write");
    }

}
