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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
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
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.BeforeClass;
import org.junit.Test;

import com.jcabi.matchers.RegexMatchers;

/**
 * Unit tests for {@link CSRBuilder}.
 *
 * @author Richard "Shred" Körber
 */
public class CSRBuilderTest {

    private static KeyPair testKey;

    @BeforeClass
    public static void setup() {
        testKey = KeyPairUtils.createKeyPair(512);
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

        builder.setCountry("XX");
        builder.setLocality("Testville");
        builder.setOrganization("Testing Co");
        builder.setOrganizationalUnit("Testunit");
        builder.setState("ABC");

        assertThat(builder.toString(), is("CN=abc.de,C=XX,L=Testville,O=Testing Co,"
                        + "OU=Testunit,ST=ABC,"
                        + "DNS=abc.de,DNS=fg.hi,DNS=jklm.no,DNS=pqr.st,DNS=uv.wx,DNS=y.z"));

        builder.sign(testKey);

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
    @SuppressWarnings("unchecked")
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
        assertThat(names.getNames(), arrayContaining(new GeneralNameMatcher("abc.de"),
                        new GeneralNameMatcher("fg.hi"), new GeneralNameMatcher("jklm.no"),
                        new GeneralNameMatcher("pqr.st"), new GeneralNameMatcher("uv.wx"),
                        new GeneralNameMatcher("y.z")));
    }

    /**
     * Checks if the {@link CSRBuilder#write(java.io.Writer)} method generates a correct
     * CSR PEM file.
     */
    private void writerTest(CSRBuilder builder) throws IOException, PEMException {
        // Write CSR to PEM
        String pem;
        try (StringWriter out = new StringWriter()) {
            builder.write(out);
            pem = out.toString();
        }

        // Make sure PEM file is properly formatted
        assertThat(pem, RegexMatchers.matchesPattern(
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

        public GeneralNameMatcher(String expectedValue) {
            this.expectedValue = expectedValue;
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof GeneralName)) {
                return false;
            }

            GeneralName gn = (GeneralName) item;

            return gn.getTagNo() == GeneralName.dNSName
                            && expectedValue.equals(DERIA5String.getInstance(gn.getName()).getString());
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
            if (gn.getTagNo() != GeneralName.dNSName) {
                description.appendText("is not DNS");
            } else {
                description.appendText("was ").appendValue(DERIA5String.getInstance(gn.getName()).getString());
            }
        }
    }

}
