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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;
import static org.shredzone.acme4j.toolbox.AcmeUtils.toAce;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.Nullable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.shredzone.acme4j.Identifier;

/**
 * Generator for a CSR (Certificate Signing Request) suitable for ACME servers.
 * <p>
 * Requires {@code Bouncy Castle}. The {@link org.bouncycastle.jce.provider.BouncyCastleProvider}
 * must also be added as security provider.
 */
public class CSRBuilder {
    private static final String SIGNATURE_ALG = "SHA256withRSA";
    private static final String EC_SIGNATURE_ALG = "SHA256withECDSA";

    private final X500NameBuilder namebuilder = new X500NameBuilder(X500Name.getDefaultStyle());
    private final List<String> namelist = new ArrayList<>();
    private final List<InetAddress> iplist = new ArrayList<>();
    private @Nullable PKCS10CertificationRequest csr = null;
    
    /**
     * Adds a domain name to the CSR. The first domain name added will also be the
     * <em>Common Name</em>. All domain names will be added as <em>Subject Alternative
     * Name</em>.
     * <p>
     * IDN domain names are ACE encoded automatically.
     * <p>
     * For wildcard certificates, the domain name must be prefixed with {@code "*."}.
     *
     * @param domain
     *            Domain name to add
     */
    public void addDomain(String domain) {
        String ace = toAce(requireNonNull(domain));
        if (namelist.isEmpty()) {
            namebuilder.addRDN(BCStyle.CN, ace);
        }
        namelist.add(ace);
    }

    /**
     * Adds a {@link Collection} of domains.
     * <p>
     * IDN domain names are ACE encoded automatically.
     *
     * @param domains
     *            Collection of domain names to add
     */
    public void addDomains(Collection<String> domains) {
        domains.forEach(this::addDomain);
    }

    /**
     * Adds multiple domain names.
     * <p>
     * IDN domain names are ACE encoded automatically.
     *
     * @param domains
     *            Domain names to add
     */
    public void addDomains(String... domains) {
        Arrays.stream(domains).forEach(this::addDomain);
    }

    /**
     * Adds an {@link InetAddress}. All IP addresses will be set as iPAddress <em>Subject
     * Alternative Name</em>.
     *
     * @param address
     *            {@link InetAddress} to add
     * @since 2.4
     */
    public void addIP(InetAddress address) {
        iplist.add(requireNonNull(address));
    }

    /**
     * Adds a {@link Collection} of IP addresses.
     *
     * @param ips
     *            Collection of IP addresses to add
     * @since 2.4
     */
    public void addIPs(Collection<InetAddress> ips) {
        ips.forEach(this::addIP);
    }

    /**
     * Adds multiple IP addresses.
     *
     * @param ips
     *            IP addresses to add
     * @since 2.4
     */
    public void addIPs(InetAddress... ips) {
        Arrays.stream(ips).forEach(this::addIP);
    }

    /**
     * Adds an {@link Identifier}. Only DNS and IP types are supported.
     *
     * @param id
     *            {@link Identifier} to add
     * @since 2.7
     */
    public void addIdentifier(Identifier id) {
        requireNonNull(id);
        if (Identifier.TYPE_DNS.equals(id.getType())) {
            addDomain(id.getDomain());
        } else if (Identifier.TYPE_IP.equals(id.getType())) {
            addIP(id.getIP());
        } else {
            throw new IllegalArgumentException("Unknown identifier type: " + id.getType());
        }
    }

    /**
     * Adds a {@link Collection} of {@link Identifier}.
     *
     * @param ids
     *            Collection of Identifiers to add
     * @since 2.7
     */
    public void addIdentifiers(Collection<Identifier> ids) {
        ids.forEach(this::addIdentifier);
    }

    /**
     * Adds multiple {@link Identifier}.
     *
     * @param ids
     *            Identifiers to add
     * @since 2.7
     */
    public void addIdentifiers(Identifier... ids) {
        Arrays.stream(ids).forEach(this::addIdentifier);
    }
    
    /**
     * Sets an entry of the subject used for the CSR
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     * @param attName The BCStyle attribute name
     * @param value The value
     */
    public void addValue(String attName, String value) {
        ASN1ObjectIdentifier oid = X500Name.getDefaultStyle().attrNameToOID(requireNonNull(attName, "attribute name must not be null"));
        addValue(oid, value);
    }

    /**
     * Sets an entry of the subject used for the CSR
     * <p>
     * Note that it is at the discretion of the ACME server to accept this parameter.
     * @param oid The OID of the attribute to be added
     * @param value The value
     */
    public void addValue(ASN1ObjectIdentifier oid, String value) {
        if (requireNonNull(oid, "OID must not be null").equals(BCStyle.CN)) {
            addDomain(value);
            return;
        }
        namebuilder.addRDN(oid, requireNonNull(value, "attribute value must not be null"));
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
     * Signs the completed CSR.
     *
     * @param keypair
     *            {@link KeyPair} to sign the CSR with
     */
    public void sign(KeyPair keypair) throws IOException {
        Objects.requireNonNull(keypair, "keypair");
        if (namelist.isEmpty() && iplist.isEmpty()) {
            throw new IllegalStateException("No domain or IP address was set");
        }

        try {
            int ix = 0;
            GeneralName[] gns = new GeneralName[namelist.size() + iplist.size()];
            for (String name : namelist) {
                gns[ix++] = new GeneralName(GeneralName.dNSName, name);
            }
            for (InetAddress ip : iplist) {
                gns[ix++] = new GeneralName(GeneralName.iPAddress, ip.getHostAddress());
            }
            GeneralNames subjectAltName = new GeneralNames(gns);

            PKCS10CertificationRequestBuilder p10Builder =
                            new JcaPKCS10CertificationRequestBuilder(namebuilder.build(), keypair.getPublic());

            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

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
        if (!namelist.isEmpty()) {
            sb.append(namelist.stream().collect(joining(",DNS=", ",DNS=", "")));
        }
        if (!iplist.isEmpty()) {
            sb.append(iplist.stream()
                    .map(InetAddress::getHostAddress)
                    .collect(joining(",IP=", ",IP=", "")));
        }
        return sb.toString();
    }

}
