/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j;

import static java.util.Collections.unmodifiableList;

import java.io.IOException;
import java.io.Writer;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate and its certificate chain.
 * <p>
 * Note that a certificate is immutable once it is issued. For renewal, a new certificate
 * must be ordered.
 */
public class Certificate extends AcmeResource {
    private static final long serialVersionUID = 7381527770159084201L;
    private static final Logger LOG = LoggerFactory.getLogger(Certificate.class);

    private ArrayList<X509Certificate> certChain = null;
    private ArrayList<URL> alternates = null;

    protected Certificate(Login login, URL certUrl) {
        super(login, certUrl);
    }

    /**
     * Downloads the certificate chain.
     * <p>
     * The certificate is downloaded lazily by the other methods. So usually there is no
     * need to invoke this method, unless the download is to be enforced. If the
     * certificate has been downloaded already, nothing will happen.
     *
     * @throws AcmeException
     *             if the certificate could not be downloaded
     */
    public void download() throws AcmeException {
        if (certChain == null) {
            LOG.debug("download");
            try (Connection conn = connect()) {
                conn.sendRequest(getLocation(), getSession());
                alternates = new ArrayList<>(conn.getLinks("alternate"));
                certChain = new ArrayList<>(conn.readCertificates());
            }
        }
    }

    /**
     * Returns the created certificate.
     *
     * @return The created end-entity {@link X509Certificate} without issuer chain.
     */
    public X509Certificate getCertificate() {
        lazyDownload();
        return certChain.get(0);
    }

    /**
     * Returns the created certificate and issuer chain.
     *
     * @return The created end-entity {@link X509Certificate} and issuer chain. The first
     *         certificate is always the end-entity certificate, followed by the
     *         intermediate certificates required to build a path to a trusted root.
     */
    public List<X509Certificate> getCertificateChain() {
        lazyDownload();
        return unmodifiableList(certChain);
    }

    /**
     * Returns URLs to alternate certificate chains.
     *
     * @return Alternate certificate chains, or empty if there are none.
     */
    public List<URL> getAlternates() {
        lazyDownload();
        if (alternates != null) {
            return unmodifiableList(alternates);
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Writes the certificate to the given writer. It is written in PEM format, with the
     * end-entity cert coming first, followed by the intermediate ceritificates.
     *
     * @param out
     *            {@link Writer} to write to. The writer is not closed after use.
     */
    public void writeCertificate(Writer out) throws IOException {
        try {
            for (X509Certificate cert : getCertificateChain()) {
                AcmeUtils.writeToPem(cert.getEncoded(), AcmeUtils.PemLabel.CERTIFICATE, out);
            }
        } catch (CertificateEncodingException ex) {
            throw new IOException("Encoding error", ex);
        }
    }

    /**
     * Revokes this certificate.
     */
    public void revoke() throws AcmeException {
        revoke(null);
    }

    /**
     * Revokes this certificate.
     *
     * @param reason
     *            {@link RevocationReason} stating the reason of the revocation that is
     *            used when generating OCSP responses and CRLs. {@code null} to give no
     *            reason.
     */
    public void revoke(RevocationReason reason) throws AcmeException {
        LOG.debug("revoke");
        URL resUrl = getSession().resourceUrl(Resource.REVOKE_CERT);
        if (resUrl == null) {
            throw new AcmeException("Server does not allow certificate revocation");
        }

        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putBase64("certificate", getCertificate().getEncoded());
            if (reason != null) {
                claims.put("reason", reason.getReasonCode());
            }

            conn.sendSignedRequest(resUrl, claims, getSession(), getLogin().getKeyPair());
        } catch (CertificateEncodingException ex) {
            throw new AcmeProtocolException("Invalid certificate", ex);
        }
    }

    /**
     * Revoke a certificate. This call is meant to be used for revoking certificates if
     * the account's key pair was lost.
     *
     * @param session
     *            {@link Session} connected to the ACME server
     * @param domainKeyPair
     *            Key pair the CSR was signed with
     * @param cert
     *            The {@link X509Certificate} to be revoked
     * @param reason
     *            {@link RevocationReason} stating the reason of the revocation that is
     *            used when generating OCSP responses and CRLs. {@code null} to give no
     *            reason.
     */
    public static void revoke(Session session, KeyPair domainKeyPair, X509Certificate cert,
            RevocationReason reason) throws AcmeException {
        LOG.debug("revoke immediately");

        URL resUrl = session.resourceUrl(Resource.REVOKE_CERT);
        if (resUrl == null) {
            throw new AcmeException("Server does not allow certificate revocation");
        }

        try (Connection conn = session.provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putBase64("certificate", cert.getEncoded());
            if (reason != null) {
                claims.put("reason", reason.getReasonCode());
            }

            conn.sendSignedRequest(resUrl, claims, session, domainKeyPair);
        } catch (CertificateEncodingException ex) {
            throw new AcmeProtocolException("Invalid certificate", ex);
        }
    }

    /**
     * Lazily downloads the certificate. Throws a runtime {@link AcmeLazyLoadingException}
     * if the download failed.
     */
    private void lazyDownload() {
        try {
            download();
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(this, ex);
        }
    }

}
