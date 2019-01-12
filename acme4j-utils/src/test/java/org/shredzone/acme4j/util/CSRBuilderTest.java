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
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link CSRBuilder}.
 */
public class CSRBuilderTest {

    private static KeyPair testKey;
    private static KeyPair testEcKey;

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());

        testKey = KeyPairUtils.createKeyPair(512);
        testEcKey = KeyPairUtils.createECKeyPair("secp256r1");
    }

    /**
     * Test if the generated CSR is plausible.
     */
    @Test
    public void testGenerate() throws IOException {
        CSRBuilder builder = new CSRBuilder();
        builder.addDomain("abc.de");
        builder.addDomain("fg.hi");
        builder.addDomains("jklm.no", "pqr.st");
        builder.addDomains(Arrays.asList("uv.wx", "y.z"));
        builder.addDomain("*.wild.card");
        builder.addIP(InetAddress.getByName("192.168.0.1"));
        builder.addIP(InetAddress.getByName("192.168.0.2"));
        builder.addIPs(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"));
        builder.addIPs(Arrays.asList(InetAddress.getByName("fd00::1"), InetAddress.getByName("fd00::2")));

        builder.setCountry("XX");
        builder.setLocality("Testville");
        builder.setOrganization("Testing Co");
        builder.setOrganizationalUnit("Testunit");
        builder.setState("ABC");

        assertThat(builder.toString(), is("CN=abc.de,C=XX,L=Testville,O=Testing Co,"
                        + "OU=Testunit,ST=ABC,"
                        + "DNS=abc.de,DNS=fg.hi,DNS=jklm.no,DNS=pqr.st,DNS=uv.wx,DNS=y.z,DNS=*.wild.card,"
                        + "IP=192.168.0.1,IP=192.168.0.2,IP=10.0.0.1,IP=10.0.0.2,"
                        + "IP=fd00:0:0:0:0:0:0:1,IP=fd00:0:0:0:0:0:0:2"));

        builder.sign(testKey);

        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr, is(notNullValue()));
        assertThat(csr.getEncoded(), is(equalTo(builder.getEncoded())));

        csrTest(csr);
        writerTest(builder);
    }

    /**
     * Test if the generated CSR is plausible using a ECDSA key.
     */
    @Test
    public void testECCGenerate() throws IOException {
        CSRBuilder builder = new CSRBuilder();
        builder.addDomain("abc.de");
        builder.addDomain("fg.hi");
        builder.addDomains("jklm.no", "pqr.st");
        builder.addDomains(Arrays.asList("uv.wx", "y.z"));
        builder.addDomain("*.wild.card");
        builder.addIP(InetAddress.getByName("192.168.0.1"));
        builder.addIP(InetAddress.getByName("192.168.0.2"));
        builder.addIPs(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"));
        builder.addIPs(Arrays.asList(InetAddress.getByName("fd00::1"), InetAddress.getByName("fd00::2")));

        builder.setCountry("XX");
        builder.setLocality("Testville");
        builder.setOrganization("Testing Co");
        builder.setOrganizationalUnit("Testunit");
        builder.setState("ABC");

        assertThat(builder.toString(), is("CN=abc.de,C=XX,L=Testville,O=Testing Co,"
                        + "OU=Testunit,ST=ABC,"
                        + "DNS=abc.de,DNS=fg.hi,DNS=jklm.no,DNS=pqr.st,DNS=uv.wx,DNS=y.z,DNS=*.wild.card,"
                        + "IP=192.168.0.1,IP=192.168.0.2,IP=10.0.0.1,IP=10.0.0.2,"
                        + "IP=fd00:0:0:0:0:0:0:1,IP=fd00:0:0:0:0:0:0:2"));

        builder.sign(testEcKey);

        PKCS10CertificationRequest csr = builder.getCSR();
        assertThat(csr, is(notNullValue()));
        assertThat(csr.getEncoded(), is(equalTo(builder.getEncoded())));

        csrTest(csr);
        writerTest(builder);
    }

    /**
     * Checks if the CSR contains the right parameters.
     * <p>
     * This is not supposed to be a Bouncy Castle test. If the
     * {@link PKCS10CertificationRequest} contains the right parameters, we assume that
     * Bouncy Castle encodes it properly.
     */
    private void csrTest(PKCS10CertificationRequest csr) {
        X500Name name = csr.getSubject();
        assertThat(name.getRDNs(BCStyle.CN), arrayContaining(new RDNMatcher("abc.de")));
        assertThat(name.getRDNs(BCStyle.C), arrayContaining(new RDNMatcher("XX")));
        assertThat(name.getRDNs(BCStyle.L), arrayContaining(new RDNMatcher("Testville")));
        assertThat(name.getRDNs(BCStyle.O), arrayContaining(new RDNMatcher("Testing Co")));
        assertThat(name.getRDNs(BCStyle.OU), arrayContaining(new RDNMatcher("Testunit")));
        assertThat(name.getRDNs(BCStyle.ST), arrayContaining(new RDNMatcher("ABC")));

        Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(attr.length, is(1));
        ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions.length, is(1));
        GeneralNames names = GeneralNames.fromExtensions((Extensions) extensions[0], Extension.subjectAlternativeName);
        assertThat(names.getNames(), arrayContaining(
                        new GeneralNameMatcher("abc.de", GeneralName.dNSName),
                        new GeneralNameMatcher("fg.hi", GeneralName.dNSName),
                        new GeneralNameMatcher("jklm.no", GeneralName.dNSName),
                        new GeneralNameMatcher("pqr.st", GeneralName.dNSName),
                        new GeneralNameMatcher("uv.wx", GeneralName.dNSName),
                        new GeneralNameMatcher("y.z", GeneralName.dNSName),
                        new GeneralNameMatcher("*.wild.card", GeneralName.dNSName),
                        new GeneralNameMatcher("192.168.0.1", GeneralName.iPAddress),
                        new GeneralNameMatcher("192.168.0.2", GeneralName.iPAddress),
                        new GeneralNameMatcher("10.0.0.1", GeneralName.iPAddress),
                        new GeneralNameMatcher("10.0.0.2", GeneralName.iPAddress),
                        new GeneralNameMatcher("fd00:0:0:0:0:0:0:1", GeneralName.iPAddress),
                        new GeneralNameMatcher("fd00:0:0:0:0:0:0:2", GeneralName.iPAddress)));
    }

    /**
     * Checks if the {@link CSRBuilder#write(java.io.Writer)} method generates a correct
     * CSR PEM file.
     */
    private void writerTest(CSRBuilder builder) throws IOException {
        // Write CSR to PEM
        String pem;
        try (StringWriter out = new StringWriter()) {
            builder.write(out);
            pem = out.toString();
        }

        // Make sure PEM file is properly formatted
        assertThat(pem, matchesPattern(
                  "-----BEGIN CERTIFICATE REQUEST-----[\\r\\n]+"
                + "([a-zA-Z0-9/+=]+[\\r\\n]+)+"
                + "-----END CERTIFICATE REQUEST-----[\\r\\n]*"));

        // Read CSR from PEM
        PKCS10CertificationRequest readCsr;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            readCsr = (PKCS10CertificationRequest) parser.readObject();
        }

        // Verify that both keypairs are the same
        assertThat(builder.getCSR(), not(sameInstance(readCsr)));
        assertThat(builder.getEncoded(), is(equalTo(readCsr.getEncoded())));

        // OutputStream is identical?
        byte[] pemBytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemBytes = baos.toByteArray();
        }
        assertThat(new String(pemBytes, "utf-8"), is(equalTo(pem)));
    }

    /**
     * Make sure an exception is thrown when no domain is set.
     */
    @Test(expected = IllegalStateException.class)
    public void testNoDomain() throws IOException {
        CSRBuilder builder = new CSRBuilder();
        builder.sign(testKey);
    }

    /**
     * Make sure all getters will fail if the CSR is not signed.
     */
    @Test
    public void testNoSign() throws IOException {
        CSRBuilder builder = new CSRBuilder();

        try {
            builder.getCSR();
            fail("getCSR(): expected exception was not thrown");
        } catch (IllegalStateException ex) {
            // expected
        }

        try {
            builder.getEncoded();
            fail("getEncoded(): expected exception was not thrown");
        } catch (IllegalStateException ex) {
            // expected
        }

        try (StringWriter w = new StringWriter()) {
            builder.write(w);
            fail("write(): expected exception was not thrown");
        } catch (IllegalStateException ex) {
            // expected
        }
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

            if (gn.getTagNo() == GeneralName.dNSName) {
                return expectedValue.equals(DERIA5String.getInstance(gn.getName()).getString());
            }

            if (gn.getTagNo() == GeneralName.iPAddress) {
                return expectedValue.equals(getIP(gn.getName()).getHostAddress());
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
            if (gn.getTagNo() == GeneralName.dNSName) {
                description.appendText("was DNS ").appendValue(DERIA5String.getInstance(gn.getName()).getString());
            } else if (gn.getTagNo() == GeneralName.iPAddress) {
                description.appendText("was IP ").appendValue(getIP(gn.getName()).getHostAddress());
            } else {
                description.appendText("is neither DNS nor IP, but has tag " + gn.getTagNo());
            }
        }

        /**
         * Fetches the {@link InetAddress} from the given iPAddress record.
         *
         * @param name
         *            Name to convert
         * @return {@link InetAddress}
         * @throws IllegalArgumentException
         *             if the IP address could not be read
         */
        private InetAddress getIP(ASN1Encodable name) {
            try {
                return InetAddress.getByAddress(DEROctetString.getInstance(name).getOctets());
            } catch (UnknownHostException ex) {
                throw new IllegalArgumentException(ex);
            }
        }
    }

}
