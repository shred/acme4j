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
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.AcmeUtils;
import org.shredzone.acme4j.util.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate and its certificate chain.
 */
public class Certificate extends AcmeResource {
    private static final long serialVersionUID = 7381527770159084201L;
    private static final Logger LOG = LoggerFactory.getLogger(Certificate.class);

    private ArrayList<X509Certificate> certChain = null;

    protected Certificate(Session session, URL certUrl) {
        super(session);
        setLocation(certUrl);
    }

    /**
     * Creates a new instance of {@link Certificate} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location of the Certificate
     * @return {@link Certificate} bound to the session and location
     */
    public static Certificate bind(Session session, URL location) {
        return new Certificate(session, location);
    }

    /**
     * Downloads the certificate chain.
     *
     * @throws AcmeException
     *             if the certificate could not be downloaded
     */
    public void download() throws AcmeException {
        if (certChain == null) {
            LOG.debug("download");
            try (Connection conn = getSession().provider().connect()) {
                conn.sendRequest(getLocation(), getSession());
                conn.accept(HttpURLConnection.HTTP_OK);
                certChain = new ArrayList<>(conn.readCertificates());
            }
        }
    }

    /**
     * Returns the created certificate.
     *
     * @return The created end-entity {@link X509Certificate} without issuer chain.
     * @throws AcmeProtocolException
     *             if lazy downloading failed
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
     * @throws AcmeProtocolException
     *             if lazy downloading failed
     */
    public List<X509Certificate> getCertificateChain() {
        lazyDownload();
        return unmodifiableList(certChain);
    }

    /**
     * Writes the certificate to the given writer. It is written in PEM format, with the
     * end-entity cert coming first, followed by the intermediate ceritificates.
     *
     * @param out
     *            {@link Writer} to write to. The writer is not closed after use.
     * @throws AcmeProtocolException
     *             if lazy downloading failed
     */
    public void writeCertificate(Writer out) throws IOException {
        try {
            for (X509Certificate cert : getCertificateChain()) {
                AcmeUtils.writeToPem(cert.getEncoded(), "CERTIFICATE", out);
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
            throw new AcmeProtocolException("CA does not support certificate revocation");
        }

        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource(Resource.REVOKE_CERT);
            claims.putBase64("certificate", getCertificate().getEncoded());
            if (reason != null) {
                claims.put("reason", reason.getReasonCode());
            }

            conn.sendSignedRequest(resUrl, claims, getSession());
            conn.accept(HttpURLConnection.HTTP_OK);
        } catch (CertificateEncodingException ex) {
            throw new AcmeProtocolException("Invalid certificate", ex);
        }
    }

    /**
     * Lazily downloads the certificate. Throws a runtime {@link AcmeProtocolException} if
     * the download failed.
     */
    private void lazyDownload() {
        try {
            download();
        } catch (AcmeException ex) {
            throw new AcmeProtocolException("Could not lazily download certificate", ex);
        }
    }

}
