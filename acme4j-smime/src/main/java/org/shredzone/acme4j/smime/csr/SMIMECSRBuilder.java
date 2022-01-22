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
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.smime.EmailIdentifier;

/**
 * Generator for an S/MIME CSR (Certificate Signing Request) suitable for ACME servers.
 * <p>
 * Requires {@code Bouncy Castle}. The {@link org.bouncycastle.jce.provider.BouncyCastleProvider}
 * must also be added as security provider.
 * <p>
 * A {@code javax.mail} implementation must be present in the classpath.
 *
 * @since 2.12
 */
public class SMIMECSRBuilder {
    private static final String SIGNATURE_ALG = "SHA256withRSA";
    private static final String EC_SIGNATURE_ALG = "SHA256withECDSA";

    private final X500NameBuilder namebuilder = new X500NameBuilder(X500Name.getDefaultStyle());
    private final List<InternetAddress> emaillist = new ArrayList<>();
    private @Nullable PKCS10CertificationRequest csr = null;
    private KeyUsageType keyUsageType = KeyUsageType.SIGNING_AND_ENCRYPTION;

    /**
     * Adds an {@link InternetAddress}. The first address is also used as CN.
     *
     * @param email
     *            {@link InternetAddress} to add
     */
    public void addEmail(InternetAddress email) {
        if (emaillist.isEmpty()) {
            namebuilder.addRDN(BCStyle.CN, email.getAddress());
        }
        emaillist.add(email);
    }

    /**
     * Adds multiple {@link InternetAddress}.
     *
     * @param emails
     *            Collection of {@link InternetAddress} to add
     */
    public void addEmails(Collection<InternetAddress> emails) {
        emails.forEach(this::addEmail);
    }

    /**
     * Adds multiple {@link InternetAddress}.
     *
     * @param emails
     *            {@link InternetAddress} to add
     */
    public void addEmails(InternetAddress... emails) {
        Arrays.stream(emails).forEach(this::addEmail);
    }

    /**
     * Adds an email {@link Identifier}.
     *
     * @param id
     *            {@link Identifier} to add
     */
    public void addIdentifier(Identifier id) {
        requireNonNull(id);
        if (!EmailIdentifier.TYPE_EMAIL.equals(id.getType())) {
            throw new AcmeProtocolException("Expected type email, but got " + id.getType());
        }

        try {
            addEmail(new InternetAddress(id.getValue()));
        } catch (AddressException ex) {
            throw new AcmeProtocolException("bad email address", ex);
        }
    }

    /**
     * Adds a {@link Collection} of email {@link Identifier}.
     *
     * @param ids
     *            Collection of Identifier to add
     */
    public void addIdentifiers(Collection<Identifier> ids) {
        ids.forEach(this::addIdentifier);
    }

    /**
     * Adds multiple email {@link Identifier}.
     *
     * @param ids
     *            Identifier to add
     */
    public void addIdentifiers(Identifier... ids) {
        Arrays.stream(ids).forEach(this::addIdentifier);
    }

    /**
     * Sets the organization.
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     */
    public void setOrganization(String o) {
        namebuilder.addRDN(BCStyle.O, requireNonNull(o));
    }

    /**
     * Sets the organizational unit.
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     */
    public void setOrganizationalUnit(String ou) {
        namebuilder.addRDN(BCStyle.OU, requireNonNull(ou));
    }

    /**
     * Sets the city or locality.
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     */
    public void setLocality(String l) {
        namebuilder.addRDN(BCStyle.L, requireNonNull(l));
    }

    /**
     * Sets the state or province.
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     */
    public void setState(String st) {
        namebuilder.addRDN(BCStyle.ST, requireNonNull(st));
    }

    /**
     * Sets the country.
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     */
    public void setCountry(String c) {
        namebuilder.addRDN(BCStyle.C, requireNonNull(c));
    }

    /**
     * Sets the key usage type for S/MIME certificates.
     * <p>
     * By default, the S/MIME certificate will be suitable for both signing and
     * encryption.
     */
    public void setKeyUsageType(KeyUsageType keyUsageType) {
        requireNonNull(keyUsageType, "keyUsageType");
        this.keyUsageType = keyUsageType;
    }

    /**
     * Signs the completed S/MIME CSR.
     *
     * @param keypair
     *            {@link KeyPair} to sign the CSR with
     */
    public void sign(KeyPair keypair) throws IOException {
        requireNonNull(keypair, "keypair");
        if (emaillist.isEmpty()) {
            throw new IllegalStateException("No email address was set");
        }

        try {
            int ix = 0;
            GeneralName[] gns = new GeneralName[emaillist.size()];
            for (InternetAddress email : emaillist) {
                gns[ix++] = new GeneralName(GeneralName.rfc822Name, email.getAddress());
            }
            GeneralNames subjectAltName = new GeneralNames(gns);

            PKCS10CertificationRequestBuilder p10Builder =
                            new JcaPKCS10CertificationRequestBuilder(namebuilder.build(), keypair.getPublic());

            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

            KeyUsage keyUsage = new KeyUsage(keyUsageType.getKeyUsageBits());
            extensionsGenerator.addExtension(Extension.keyUsage, true, keyUsage);

            p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

            PrivateKey pk = keypair.getPrivate();
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(
                            pk instanceof ECKey ? EC_SIGNATURE_ALG : SIGNATURE_ALG);
            ContentSigner signer = csBuilder.build(pk);

            csr = p10Builder.build(signer);
        } catch (OperatorCreationException ex) {
            throw new IOException("Could not generate CSR", ex);
        }
    }

    /**
     * Gets the PKCS#10 certification request.
     */
    public PKCS10CertificationRequest getCSR() {
        if (csr == null) {
            throw new IllegalStateException("sign CSR first");
        }

        return csr;
    }

    /**
     * Gets an encoded PKCS#10 certification request.
     */
    public byte[] getEncoded() throws IOException {
        return getCSR().getEncoded();
    }

    /**
     * Writes the signed certificate request to a {@link Writer}.
     *
     * @param w
     *            {@link Writer} to write the PEM file to. The {@link Writer} is closed
     *            after use.
     */
    public void write(Writer w) throws IOException {
        if (csr == null) {
            throw new IllegalStateException("sign CSR first");
        }

        try (PemWriter pw = new PemWriter(w)) {
            pw.writeObject(new PemObject("CERTIFICATE REQUEST", getEncoded()));
        }
    }

    /**
     * Writes the signed certificate request to an {@link OutputStream}.
     *
     * @param out
     *            {@link OutputStream} to write the PEM file to. The {@link OutputStream}
     *            is closed after use.
     */
    public void write(OutputStream out) throws IOException {
        write(new OutputStreamWriter(out, UTF_8));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(namebuilder.build());
        if (!emaillist.isEmpty()) {
            sb.append(emaillist.stream()
                    .map(InternetAddress::getAddress)
                    .collect(joining(",EMAIL=", ",EMAIL=", "")));
        }
        sb.append(",TYPE=").append(keyUsageType);
        return sb.toString();
    }

}
