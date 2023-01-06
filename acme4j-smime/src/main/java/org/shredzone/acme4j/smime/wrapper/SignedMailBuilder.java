/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.wrapper;

import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;

/**
 * Creates a {@link SignedMail} instance from a signed message.
 *
 * @since 2.16
 */
public class SignedMailBuilder {
    private static final AtomicReference<KeyStore> CACERTS_TRUSTSTORE = new AtomicReference<>();

    private Session mailSession = Session.getDefaultInstance(new Properties());
    private boolean relaxed = false;

    @Nullable
    private PKIXParameters pkixParameters = null;

    /**
     * Uses the given truststore for certificate validation.
     *
     * @param trustStore {@link KeyStore} to use.
     * @return itself
     */
    public SignedMailBuilder withTrustStore(KeyStore trustStore)
            throws KeyStoreException, InvalidAlgorithmParameterException {
        requireNonNull(trustStore, "trustStore");
        return withPKIXParameters(new PKIXParameters(trustStore));
    }

    /**
     * Uses the given {@link X509Certificate} for certificate validation.
     *
     * @param signCert {@link X509Certificate} to use.
     * @return itself
     */
    public SignedMailBuilder withSignCert(X509Certificate signCert) {
        requireNonNull(signCert, "signCert");
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);
            ks.setCertificateEntry("cert", signCert);
            return withTrustStore(ks);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException | InvalidAlgorithmParameterException ex) {
            throw new IllegalArgumentException("Invalid certificate", ex);
        }
    }

    /**
     * Uses the given {@link PKIXParameters} for certificate validation.
     *
     * @param param {@link PKIXParameters} to use.
     * @return itself
     */
    public SignedMailBuilder withPKIXParameters(PKIXParameters param) {
        this.pkixParameters = requireNonNull(param, "param");
        return this;
    }

    /**
     * Sets a different mail {@link Session} that is used for accessing the signed
     * email body.
     *
     * @param mailSession {@link Session} to use.
     * @return itself
     */
    public SignedMailBuilder withMailSession(Session mailSession) {
        this.mailSession = requireNonNull(mailSession, "mailSession");
        return this;
    }

    /**
     * Changes relaxed validation. If enabled, headers of the signed message body are
     * preferred if present, but do not need to match the appropriate headers of the
     * envelope message.
     * <p>
     * By default, relaxed validation is disabled.
     *
     * @param relaxed sets relaxed validation mode
     * @return itself
     */
    public SignedMailBuilder relaxed(boolean relaxed) {
        this.relaxed = relaxed;
        return this;
    }

    /**
     * Validates the message signature and message headers. If validation passes, a
     * {@link SignedMail} instance is returned that gives access to the trusted mail
     * headers.
     *
     * @param message {@link Message}, must be a {@link MimeMessage}.
     * @return SignedMail containing the trusted headers.
     * @throws AcmeInvalidMessageException
     *         if the given message is invalid, its signature is invalid, or the secured
     *         headers are invalid. If this exception is thrown, the message MUST be
     *         rejected.
     */
    public SignedMail build(Message message) throws AcmeInvalidMessageException {
        requireNonNull(message, "message");
        try {
            // Check all parameters
            if (!(message instanceof MimeMessage)) {
                throw new IllegalArgumentException("Message must be a MimeMessage");
            }
            MimeMessage mimeMessage = (MimeMessage) message;

            if (!(mimeMessage.getContent() instanceof MimeMultipart)) {
                throw new AcmeProtocolException("S/MIME signed message must contain MimeMultipart");
            }

            if (pkixParameters == null) {
                pkixParameters = new PKIXParameters(getCaCertsTrustStore());
            }

            // Get the signed message
            SMIMESigned signed = new SMIMESigned((MimeMultipart) mimeMessage.getContent());

            // Validate the signature
            SignerInformation si = validateSignature(mimeMessage, pkixParameters);

            // Collect the headers
            SignedMail result = new SignedMail();

            // First import all untrusted headers from the envelope message
            result.importUntrustedHeaders(mimeMessage.getAllHeaders());

            // If there is an inner, signed message, import all signed headers
            MimeMessage content = signed.getContentAsMimeMessage(mailSession);
            if (content != null && content.isMimeType("message/rfc822")) {
                MimeMessage protectedBody = new MimeMessage(mailSession, content.getInputStream());
                if (relaxed) {
                    result.importTrustedHeadersRelaxed(protectedBody.getAllHeaders());
                } else {
                    result.importTrustedHeaders(protectedBody.getAllHeaders());
                }
            }

            // Import secured headers from the signature, if present
            result.importSignatureHeaders(si);

            // Check if all mandatory headers are trusted
            Set<String> missing = result.getMissingSecuredHeaders();
            if (!missing.isEmpty()) {
                throw new AcmeInvalidMessageException("Secured headers expected, but missing: "
                        + String.join(", ", missing));
            }

            // Check if the signer matches the mail sender
            InternetAddress signerAddress = validateSigatureSender(signed, si);
            if (!result.getFrom().equals(signerAddress)) {
                throw new AcmeInvalidMessageException("Message is not signed by the expected sender");
            }

            return result;
        } catch (IOException | MessagingException | CMSException |
                 KeyStoreException | InvalidAlgorithmParameterException ex) {
            throw new AcmeInvalidMessageException("Could not validate message signature", ex);
        }
    }

    /**
     * Validates the signature of the signed message.
     *
     * @return The {@link SignerInformation} of the valid signature.
     * @throws AcmeInvalidMessageException
     *         if the signature is invalid, or if the message was signed with more than
     *         one signature.
     */
    private SignerInformation validateSignature(MimeMessage message, PKIXParameters pkixParameters)
            throws AcmeInvalidMessageException {
        try {
            SignedMailValidator smv = new SignedMailValidator(message, pkixParameters);

            SignerInformationStore store = smv.getSignerInformationStore();
            if (store.size() != 1) {
                throw new AcmeInvalidMessageException("Expected exactly one signer, but found " + store.size());
            }
            return store.getSigners().iterator().next();
        } catch (SignedMailValidatorException ex) {
            throw new AcmeInvalidMessageException("Invalid signature", ex);
        }
    }

    /**
     * Validates the signature of the sender. It MUST contain a subjectAltName extension
     * with a rfc822Name that matches the sender.
     *
     * @param signed
     *         {@link SMIMESigned} of the signed message
     * @param si
     *         {@link SignerInformation} of the message signer
     * @return The {@link InternetAddress} of the rfc822Name found in the subjectAltName
     * @throws AcmeInvalidMessageException
     *         if no signature was found, or if the signature has no subjectAltName
     *         extension with rfc822Name.
     */
    @SuppressWarnings("unchecked")
    private InternetAddress validateSigatureSender(SMIMESigned signed, SignerInformation si)
            throws AcmeInvalidMessageException {
        Collection<X509CertificateHolder> certCollection = signed.getCertificates().getMatches(si.getSID());
        if (certCollection.isEmpty()) {
            throw new AcmeInvalidMessageException("Could not find certificate for signer ID "
                    + si.getSID().toString());
        }
        X509CertificateHolder ch = certCollection.iterator().next();

        GeneralNames gns = GeneralNames.fromExtensions(ch.getExtensions(), Extension.subjectAlternativeName);
        if (gns == null) {
            throw new AcmeInvalidMessageException("Certificate does not have a subjectAltName extension");
        }

        for (GeneralName name : gns.getNames()) {
            if (name.getTagNo() == GeneralName.rfc822Name) {
                try {
                    return new InternetAddress(name.getName().toString());
                } catch (AddressException ex) {
                    throw new AcmeInvalidMessageException("Invalid certificate email address: "
                            + name.getName().toString(), ex);
                }
            }
        }

        throw new AcmeInvalidMessageException("No rfc822Name found in subjectAltName extension");
    }

    /**
     * Generates a truststore from Java's own cacerts file. The result is cached.
     *
     * @return CaCerts truststore
     */
    private static KeyStore getCaCertsTrustStore() {
        KeyStore caCerts = CACERTS_TRUSTSTORE.get();
        if (caCerts == null) {
            String javaHome = System.getProperty("java.home");
            String caFileName = javaHome + File.separator + "lib" + File.separator
                    + "security" + File.separator + "cacerts";

            try (InputStream in = new FileInputStream(caFileName)) {
                caCerts = KeyStore.getInstance("JKS");
                caCerts.load(in, "changeit".toCharArray());
                CACERTS_TRUSTSTORE.set(caCerts);
            } catch (KeyStoreException | IOException | CertificateException |
                     NoSuchAlgorithmException ex) {
                throw new IllegalStateException("Cannot access cacerts", ex);
            }
        }
        return caCerts;
    }

}
