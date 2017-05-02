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
import static java.util.stream.Collectors.toCollection;

import java.io.IOException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.AcmeUtils;
import org.shredzone.acme4j.util.JSONBuilder;
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

                Collection<URI> alternateList = conn.getLinks("alternate");
                if (alternateList != null) {
                    alternates = alternateList.stream()
                             .map(AcmeUtils::toURL)
                             .collect(toCollection(ArrayList::new));
                }

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
            throw new AcmeProtocolException("CA does not support certificate revocation");
        }

        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
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
