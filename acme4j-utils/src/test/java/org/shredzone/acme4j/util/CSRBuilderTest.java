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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Identifier;

/**
 * Unit tests for {@link CSRBuilder}.
 */
public class CSRBuilderTest {

    private static KeyPair testKey;
    private static KeyPair testEcKey;

    /**
     * Add provider, create some key pairs
     */
    @BeforeAll
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
        var builder = createBuilderWithValues();

        builder.sign(testKey);

        var csr = builder.getCSR();
        assertThat(csr).isNotNull();
        assertThat(csr.getEncoded()).isEqualTo(builder.getEncoded());

        csrTest(csr);
        writerTest(builder);
    }

    /**
     * Test if the generated CSR is plausible using a ECDSA key.
     */
    @Test
    public void testECCGenerate() throws IOException {
        var builder = createBuilderWithValues();

        builder.sign(testEcKey);

        var csr = builder.getCSR();
        assertThat(csr).isNotNull();
        assertThat(csr.getEncoded()).isEqualTo(builder.getEncoded());

        csrTest(csr);
        writerTest(builder);
    }

    /**
     * Make sure an exception is thrown when no domain is set.
     */
    @Test
    public void testNoDomain() {
        var ise = assertThrows(IllegalStateException.class, () -> {
            var builder = new CSRBuilder();
            builder.sign(testKey);
        });
        assertThat(ise.getMessage())
            .isEqualTo("No domain or IP address was set");
    }

    /**
     * Make sure an exception is thrown when an unknown identifier type is used.
     */
    @Test
    public void testUnknownType() {
        var iae = assertThrows(IllegalArgumentException.class, () -> {
            var builder = new CSRBuilder();
            builder.addIdentifier(new Identifier("UnKnOwN", "123"));
        });
        assertThat(iae.getMessage())
            .isEqualTo("Unknown identifier type: UnKnOwN");
    }

    /**
     * Make sure all getters will fail if the CSR is not signed.
     */
    @Test
    public void testNoSign() {
        var builder = new CSRBuilder();

        assertThatExceptionOfType(IllegalStateException.class)
            .isThrownBy(builder::getCSR)
            .as("getCSR()")
            .withMessage("sign CSR first");
        
        assertThatExceptionOfType(IllegalStateException.class)
            .isThrownBy(builder::getEncoded)
            .as("getCSR()")
            .withMessage("sign CSR first");

        assertThatExceptionOfType(IllegalStateException.class)
            .isThrownBy(() -> {
                try (StringWriter w = new StringWriter()) {
                    builder.write(w);
                }
            })
            .as("builder.write()")
            .withMessage("sign CSR first");
    }
    
    /**
     * Checks that addValue behaves correctly in dependence of the
     * attributes being added. If a common name is set, it should
     * be handled in the same way when it's added by using
     * <code>addDomain</code>
     */
    @Test
    public void testAddAttrValues() {
        var builder = new CSRBuilder();
        String invAttNameExMessage = assertThrows(IllegalArgumentException.class,
                () -> X500Name.getDefaultStyle().attrNameToOID("UNKNOWNATT")).getMessage();
        
        assertThat(builder.toString()).isEqualTo("");
        
        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> new CSRBuilder().addValue((String) null, "value"))
            .as("addValue(String, String)");
        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> new CSRBuilder().addValue((ASN1ObjectIdentifier) null, "value"))
            .as("addValue(ASN1ObjectIdentifier, String)");
        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> new CSRBuilder().addValue("C", null))
            .as("addValue(String, null)");
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> new CSRBuilder().addValue("UNKNOWNATT", "val"))
            .as("addValue(String, null)")
            .withMessage(invAttNameExMessage);
        
        assertThat(builder.toString()).isEqualTo("");

        builder.addValue("C", "DE");
        assertThat(builder.toString()).isEqualTo("C=DE");
        builder.addValue("E", "contact@example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com");
        builder.addValue("CN", "firstcn.example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com,CN=firstcn.example.com,DNS=firstcn.example.com");
        builder.addValue("CN", "scnd.example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com,CN=firstcn.example.com,DNS=firstcn.example.com,DNS=scnd.example.com");
        
        builder = new CSRBuilder();
        builder.addValue(BCStyle.C, "DE");
        assertThat(builder.toString()).isEqualTo("C=DE");
        builder.addValue(BCStyle.EmailAddress, "contact@example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com");
        builder.addValue(BCStyle.CN, "firstcn.example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com,CN=firstcn.example.com,DNS=firstcn.example.com");
        builder.addValue(BCStyle.CN, "scnd.example.com");
        assertThat(builder.toString()).isEqualTo("C=DE,E=contact@example.com,CN=firstcn.example.com,DNS=firstcn.example.com,DNS=scnd.example.com");
    }

    private CSRBuilder createBuilderWithValues() throws UnknownHostException {
        var builder = new CSRBuilder();
        builder.addDomain("abc.de");
        builder.addDomain("fg.hi");
        builder.addDomains("jklm.no", "pqr.st");
        builder.addDomains(Arrays.asList("uv.wx", "y.z"));
        builder.addDomain("*.wild.card");
        builder.addIP(InetAddress.getByName("192.168.0.1"));
        builder.addIP(InetAddress.getByName("192.168.0.2"));
        builder.addIPs(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"));
        builder.addIPs(Arrays.asList(InetAddress.getByName("fd00::1"), InetAddress.getByName("fd00::2")));
        builder.addIdentifier(Identifier.dns("ide1.nt"));
        builder.addIdentifier(Identifier.ip("192.168.5.5"));
        builder.addIdentifiers(Identifier.dns("ide2.nt"), Identifier.ip("192.168.5.6"));
        builder.addIdentifiers(Arrays.asList(Identifier.dns("ide3.nt"), Identifier.ip("192.168.5.7")));

        builder.setCountry("XX");
        builder.setLocality("Testville");
        builder.setOrganization("Testing Co");
        builder.setOrganizationalUnit("Testunit");
        builder.setState("ABC");

        assertThat(builder.toString()).isEqualTo("CN=abc.de,C=XX,L=Testville,O=Testing Co,"
                        + "OU=Testunit,ST=ABC,"
                        + "DNS=abc.de,DNS=fg.hi,DNS=jklm.no,DNS=pqr.st,DNS=uv.wx,DNS=y.z,DNS=*.wild.card,"
                        + "DNS=ide1.nt,DNS=ide2.nt,DNS=ide3.nt,"
                        + "IP=192.168.0.1,IP=192.168.0.2,IP=10.0.0.1,IP=10.0.0.2,"
                        + "IP=fd00:0:0:0:0:0:0:1,IP=fd00:0:0:0:0:0:0:2,"
                        + "IP=192.168.5.5,IP=192.168.5.6,IP=192.168.5.7");
        return builder;
    }

    /**
     * Checks if the CSR contains the right parameters.
     * <p>
     * This is not supposed to be a Bouncy Castle test. If the
     * {@link PKCS10CertificationRequest} contains the right parameters, we assume that
     * Bouncy Castle encodes it properly.
     */
    private void csrTest(PKCS10CertificationRequest csr) {
        var name = csr.getSubject();
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(name.getRDNs(BCStyle.CN)).as("CN")
                    .extracting(rdn -> rdn.getFirst().getValue().toString())
                    .contains("abc.de");
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

        var attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(attr).hasSize(1);

        var extensions = attr[0].getAttrValues().toArray();
        assertThat(extensions).hasSize(1);

        var names = GeneralNames.fromExtensions((Extensions) extensions[0], Extension.subjectAlternativeName);
        assertThat(names.getNames())
                .filteredOn(gn -> gn.getTagNo() == GeneralName.dNSName)
                .extracting(gn -> ASN1IA5String.getInstance(gn.getName()).getString())
                .containsExactlyInAnyOrder("abc.de", "fg.hi", "jklm.no", "pqr.st",
                        "uv.wx", "y.z", "*.wild.card", "ide1.nt", "ide2.nt", "ide3.nt");

        assertThat(names.getNames())
                .filteredOn(gn -> gn.getTagNo() == GeneralName.iPAddress)
                .extracting(gn -> getIP(gn.getName()).getHostAddress())
                .containsExactlyInAnyOrder("192.168.0.1", "192.168.0.2", "10.0.0.1",
                        "10.0.0.2", "fd00:0:0:0:0:0:0:1", "fd00:0:0:0:0:0:0:2",
                        "192.168.5.5", "192.168.5.6", "192.168.5.7");
    }

    /**
     * Checks if the {@link CSRBuilder#write(java.io.Writer)} method generates a correct
     * CSR PEM file.
     */
    private void writerTest(CSRBuilder builder) throws IOException {
        // Write CSR to PEM
        String pem;
        try (var out = new StringWriter()) {
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
        try (var parser = new PEMParser(new StringReader(pem))) {
            readCsr = (PKCS10CertificationRequest) parser.readObject();
        }

        // Verify that both keypairs are the same
        assertThat(builder.getCSR()).isNotSameAs(readCsr);
        assertThat(builder.getEncoded()).isEqualTo(readCsr.getEncoded());

        // OutputStream is identical?
        byte[] pemBytes;
        try (var baos = new ByteArrayOutputStream()) {
            builder.write(baos);
            pemBytes = baos.toByteArray();
        }
        assertThat(new String(pemBytes, StandardCharsets.UTF_8)).isEqualTo(pem);
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
    private static InetAddress getIP(ASN1Encodable name) {
        try {
            return InetAddress.getByAddress(DEROctetString.getInstance(name).getOctets());
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}
