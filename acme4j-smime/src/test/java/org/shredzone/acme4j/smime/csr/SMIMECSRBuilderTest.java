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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
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
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link SMIMECSRBuilder}.
 */
public class SMIMECSRBuilderTest {

    private static KeyPair testKey;
    private static KeyPair testEcKey;

    @BeforeClass
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

        assertThat(builder.toString(), is("CN=mail@example.com,C=XX,L=Testville,"
                + "O=Testing Co,OU=Testunit,ST=ABC,"
                + "EMAIL=mail@example.com,EMAIL=info@example.com,"
                + "EMAIL=sales@example.com,EMAIL=shop@example.com,"
                + "EMAIL=support@example.com,EMAIL=help@example.com,"
                + "TYPE=SIGNING_AND_ENCRYPTION"));

        builder.sign(testKey);

        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr, is(Matchers.notNullValue()));
        assertThat(csr.getEncoded(), is(Matchers.equalTo(builder.getEncoded())));

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
        assertThat(csr, is(Matchers.notNullValue()));
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
        assertThat(csr, is(Matchers.notNullValue()));
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
        assertThat(csr, is(Matchers.notNullValue()));
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
        assertThat(name.getRDNs(BCStyle.CN), Matchers.arrayContaining(new RDNMatcher("mail@example.com")));
        assertThat(name.getRDNs(BCStyle.C), Matchers.arrayContaining(new RDNMatcher("XX")));
        assertThat(name.getRDNs(BCStyle.L), Matchers.arrayContaining(new RDNMatcher("Testville")));
        assertThat(name.getRDNs(BCStyle.O), Matchers.arrayContaining(new RDNMatcher("Testing Co")));
        assertThat(name.getRDNs(BCStyle.OU), Matchers.arrayContaining(new RDNMatcher("Testunit")));
        assertThat(name.getRDNs(BCStyle.ST), Matchers.arrayContaining(new RDNMatcher("ABC")));

        Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(attr.length, is(1));
        ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions.length, is(1));
        GeneralNames names = GeneralNames.fromExtensions((Extensions) extensions[0], Extension.subjectAlternativeName);
        assertThat(names.getNames(), Matchers.arrayContaining(
                new GeneralNameMatcher("mail@example.com", GeneralName.rfc822Name),
                new GeneralNameMatcher("info@example.com", GeneralName.rfc822Name),
                new GeneralNameMatcher("sales@example.com", GeneralName.rfc822Name),
                new GeneralNameMatcher("shop@example.com", GeneralName.rfc822Name),
                new GeneralNameMatcher("support@example.com", GeneralName.rfc822Name),
                new GeneralNameMatcher("help@example.com", GeneralName.rfc822Name)));
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
        assertThat(attr.length, is(1));
        ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions.length, is(1));
        DERBitString keyUsageBits = (DERBitString) ((Extensions) extensions[0]).getExtensionParsedValue(Extension.keyUsage);
        if (expectedUsageBits != null) {
            assertThat(keyUsageBits.intValue(), is(expectedUsageBits));
        } else {
            assertThat(keyUsageBits, is(Matchers.nullValue()));
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
        assertThat(pem, Matchers.matchesPattern(
                  "-----BEGIN CERTIFICATE REQUEST-----[\\r\\n]+"
                + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                + "-----END CERTIFICATE REQUEST-----[\\r\\n]*"));

        // Read CSR from PEM
        PKCS10CertificationRequest readCsr;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            readCsr = (PKCS10CertificationRequest) parser.readObject();
        }

        // Verify that both keypairs are the same
        assertThat(builder.getCSR(), Matchers.not(Matchers.sameInstance(readCsr)));
        assertThat(builder.getEncoded(), is(Matchers.equalTo(readCsr.getEncoded())));

        // OutputStream is identical?
        byte[] pemBytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemBytes = baos.toByteArray();
        }
        assertThat(new String(pemBytes, UTF_8), is(Matchers.equalTo(pem)));
    }

    /**
     * Make sure an exception is thrown when nothing is set.
     */
    @Test(expected = IllegalStateException.class)
    public void testNoEmail() throws IOException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();
        builder.sign(testKey);
    }

    /**
     * Make sure all getters will fail if the CSR is not signed.
     */
    @Test
    public void testNoSign() throws IOException {
        SMIMECSRBuilder builder = new SMIMECSRBuilder();

        assertThrows("getCSR", IllegalStateException.class, builder::getCSR);
        assertThrows("getEncoded", IllegalStateException.class, builder::getEncoded);
        assertThrows("write", IllegalStateException.class,() -> {
            try (StringWriter w = new StringWriter()) {
                builder.write(w);
            }
        });
    }

    /**
     * Matches {@link RDN} values.
     */
    private static class RDNMatcher extends BaseMatcher<RDN> {
        private final String expectedValue;

        public RDNMatcher(String expectedValue) {
            this.expectedValue = expectedValue;
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof RDN)) {
                return false;
            }
            return expectedValue.equals(((RDN) item).getFirst().getValue().toString());
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(expectedValue);
        }

        @Override
        public void describeMismatch(Object item, Description description) {
            if (!(item instanceof RDN)) {
                description.appendText("is a ").appendValue(item.getClass());
            } else {
                description.appendText("was ").appendValue(((RDN) item).getFirst().getValue());
            }
        }
    }

    /**
     * Matches {@link GeneralName} DNS tagged values.
     */
    private static class GeneralNameMatcher extends BaseMatcher<GeneralName> {
        private final String expectedValue;
        private final int expectedTag;

        public GeneralNameMatcher(String expectedValue, int expectedTag) {
            this.expectedTag = expectedTag;
            this.expectedValue = expectedValue;
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof GeneralName)) {
                return false;
            }

            GeneralName gn = (GeneralName) item;

            if (gn.getTagNo() != expectedTag) {
                return false;
            }

            if (gn.getTagNo() == GeneralName.rfc822Name) {
                return expectedValue.equals(DERIA5String.getInstance(gn.getName()).getString());
            }

            return false;
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(expectedValue);
        }

        @Override
        public void describeMismatch(Object item, Description description) {
            if (!(item instanceof GeneralName)) {
                description.appendText("is a ").appendValue(item.getClass());
                return;
            }

            GeneralName gn = (GeneralName) item;
            if (gn.getTagNo() == GeneralName.rfc822Name) {
                description.appendText("was EMAIL ").appendValue(DERIA5String.getInstance(gn.getName()).getString());
            } else {
                description.appendText("is not EMAIL, but has tag " + gn.getTagNo());
            }
        }
    }

}
