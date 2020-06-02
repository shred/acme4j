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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;

/**
 * Utility class offering convenience methods for certificates.
 * <p>
 * Requires {@code Bouncy Castle}. This class is part of the {@code acme4j-utils} module.
 */
public final class CertificateUtils {

    /**
     * The {@code acmeValidation} object identifier.
     *
     * @since 2.1
     */
    public static final ASN1ObjectIdentifier ACME_VALIDATION =
                    new ASN1ObjectIdentifier(TlsAlpn01Challenge.ACME_VALIDATION_OID).intern();

    private CertificateUtils() {
        // utility class without constructor
    }

    /**
     * Reads a CSR PEM file.
     *
     * @param in
     *            {@link InputStream} to read the CSR from. The {@link InputStream} is
     *            closed after use.
     * @return CSR that was read
     */
    public static PKCS10CertificationRequest readCSR(InputStream in) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object parsedObj = pemParser.readObject();
            if (!(parsedObj instanceof PKCS10CertificationRequest)) {
                throw new IOException("Not a PKCS10 CSR");
            }
            return (PKCS10CertificationRequest) parsedObj;
        }
    }

    /**
     * Creates a self-signed {@link X509Certificate} that can be used for the
     * {@link TlsAlpn01Challenge}. The certificate is valid for 7 days.
     *
     * @param keypair
     *            A domain {@link KeyPair} to be used for the challenge
     * @param id
     *            The {@link Identifier} that is to be validated
     * @param acmeValidation
     *            The value that is returned by
     *            {@link TlsAlpn01Challenge#getAcmeValidation()}
     * @return Created certificate
     * @since 2.6
     */
    public static X509Certificate createTlsAlpn01Certificate(KeyPair keypair, Identifier id, byte[] acmeValidation)
                throws IOException {
        Objects.requireNonNull(keypair, "keypair");
        Objects.requireNonNull(id, "id");
        if (acmeValidation == null || acmeValidation.length != 32) {
            throw new IllegalArgumentException("Bad acmeValidation parameter");
        }

        final long now = System.currentTimeMillis();

        X500Name issuer = new X500Name("CN=acme.invalid");
        BigInteger serial = BigInteger.valueOf(now);
        Instant notBefore = Instant.ofEpochMilli(now);
        Instant notAfter = notBefore.plus(Duration.ofDays(7));

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serial, Date.from(notBefore), Date.from(notAfter),
                    issuer, keypair.getPublic());

        GeneralName[] gns = new GeneralName[1];

        switch (id.getType()) {
            case Identifier.TYPE_DNS:
                gns[0] = new GeneralName(GeneralName.dNSName, id.getDomain());
                break;

            case Identifier.TYPE_IP:
                gns[0] = new GeneralName(GeneralName.iPAddress, id.getIP().getHostAddress());
                break;

            default:
                throw new IllegalArgumentException("Unsupported Identifier type " + id.getType());
        }
        certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(gns));
        certBuilder.addExtension(ACME_VALIDATION, true, new DEROctetString(acmeValidation));

        return buildCertificate(certBuilder::build, keypair.getPrivate());
    }

    /**
     * Creates a self-signed root certificate.
     * <p>
     * The generated certificate is only meant for testing purposes!
     *
     * @param subject
     *         This certificate's subject X.500 name.
     * @param notBefore
     *         {@link Instant} before which the certificate is not valid.
     * @param notAfter
     *         {@link Instant} after which the certificate is not valid.
     * @param keypair
     *         {@link KeyPair} that is to be used for this certificate.
     * @return Generated {@link X509Certificate}
     * @since 2.8
     */
    public static X509Certificate createTestRootCertificate(String subject,
            Instant notBefore, Instant notAfter, KeyPair keypair) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(keypair, "keypair");

        JcaX509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
                new X500Name(subject),
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Name(subject),
                keypair.getPublic()
        );

        return buildCertificate(certBuilder::build, keypair.getPrivate());
    }

    /**
     * Creates an intermediate certificate that is signed by an issuer.
     * <p>
     * The generated certificate is only meant for testing purposes!
     *
     * @param subject
     *         This certificate's subject X.500 name.
     * @param notBefore
     *         {@link Instant} before which the certificate is not valid.
     * @param notAfter
     *         {@link Instant} after which the certificate is not valid.
     * @param intermediatePublicKey
     *         {@link PublicKey} of this certificate
     * @param issuer
     *         The issuer's {@link X509Certificate}.
     * @param issuerPrivateKey
     *         {@link PrivateKey} of the issuer. This is not the private key of this
     *         intermediate certificate.
     * @return Generated {@link X509Certificate}
     * @since 2.8
     */
    public static X509Certificate createTestIntermediateCertificate(String subject,
            Instant notBefore, Instant notAfter, PublicKey intermediatePublicKey,
            X509Certificate issuer, PrivateKey issuerPrivateKey) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(intermediatePublicKey, "intermediatePublicKey");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey");

        JcaX509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
                new X500Name(issuer.getIssuerX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Name(subject),
                intermediatePublicKey
        );

        return buildCertificate(certBuilder::build, issuerPrivateKey);
    }

    /**
     * Creates a signed end entity certificate from the given CSR.
     * <p>
     * This method is only meant for testing purposes! Do not use it in a real-world CA
     * implementation.
     * <p>
     * Do not assume that real-world certificates have a similar structure. It's up to the
     * discretion of the CA which distinguished names, validity dates, extensions and
     * other parameters are transferred from the CSR to the generated certificate.
     *
     * @param csr
     *         CSR to create the certificate from
     * @param notBefore
     *         {@link Instant} before which the certificate is not valid.
     * @param notAfter
     *         {@link Instant} after which the certificate is not valid.
     * @param issuer
     *         The issuer's {@link X509Certificate}.
     * @param issuerPrivateKey
     *         {@link PrivateKey} of the issuer. This is not the private key the CSR was
     *         signed with.
     * @return Generated {@link X509Certificate}
     * @since 2.8
     */
    public static X509Certificate createTestCertificate(PKCS10CertificationRequest csr,
            Instant notBefore, Instant notAfter, X509Certificate issuer, PrivateKey issuerPrivateKey) {
        Objects.requireNonNull(csr, "csr");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey");

        try {
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuer.getIssuerX500Principal().getName()),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    csr.getSubject(),
                    jcaCsr.getPublicKey());

            Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attr.length > 0) {
                ASN1Encodable[] extensions = attr[0].getAttrValues().toArray();
                if (extensions.length > 0 && extensions[0] instanceof Extensions) {
                    GeneralNames san = GeneralNames.fromExtensions((Extensions) extensions[0], Extension.subjectAlternativeName);
                    certBuilder.addExtension(Extension.subjectAlternativeName, false, san);
                }
            }

            return buildCertificate(certBuilder::build, issuerPrivateKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | CertIOException ex) {
            throw new IllegalArgumentException("Invalid CSR", ex);
        }
    }

    /**
     * Build a {@link X509Certificate} from a builder.
     *
     * @param builder
     *         Builder method that receives a {@link ContentSigner} and returns a {@link
     *         X509CertificateHolder}.
     * @param privateKey
     *         {@link PrivateKey} to sign the certificate with
     * @return The generated {@link X509Certificate}
     */
    private static X509Certificate buildCertificate(Function<ContentSigner, X509CertificateHolder> builder, PrivateKey privateKey) {
        try {
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            byte[] cert = builder.apply(signerBuilder.build(privateKey)).getEncoded();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
        } catch (CertificateException | OperatorCreationException | IOException ex) {
            throw new IllegalArgumentException("Could not build certificate", ex);
        }
    }

}
