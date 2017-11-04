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

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate and its certificate chain.
 */
public class Certificate extends AcmeResource {
    private static final long serialVersionUID = 7381527770159084201L;
    private static final Logger LOG = LoggerFactory.getLogger(Certificate.class);
    private static final int MAX_CHAIN_LENGTH = 10;

    private URL chainCertUrl;
    private X509Certificate cert = null;
    private X509Certificate[] chain = null;

    protected Certificate(Session session, URL certUrl) {
        super(session);
        setLocation(certUrl);
    }

    protected Certificate(Session session, URL certUrl, URL chainUrl, X509Certificate cert) {
        super(session);
        setLocation(certUrl);
        this.chainCertUrl = chainUrl;
        this.cert = cert;
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
     * Returns the URL of the certificate chain. {@code null} if not known or not
     * available.
     */
    public URL getChainLocation() {
        return chainCertUrl;
    }

    /**
     * Downloads the certificate. The result is cached.
     *
     * @return {@link X509Certificate} that was downloaded
     * @throws AcmeRetryAfterException
     *             the certificate is still being created, and the server returned an
     *             estimated date when it will be ready for download. You should wait for
     *             the date given in {@link AcmeRetryAfterException#getRetryAfter()}
     *             before trying again.
     */
    public X509Certificate download() throws AcmeException {
        if (cert == null) {
            LOG.debug("download");
            try (Connection conn = getSession().provider().connect()) {
                conn.sendRequest(getLocation(), getSession());
                conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);
                conn.handleRetryAfter("certificate is not available for download yet");

                chainCertUrl = conn.getLink("up");
                cert = conn.readCertificate();
            }
        }
        return cert;
    }

    /**
     * Downloads the certificate chain. The result is cached.
     *
     * @return Chain of {@link X509Certificate}s
     * @throws AcmeRetryAfterException
     *             the certificate is still being created, and the server returned an
     *             estimated date when it will be ready for download. You should wait for
     *             the date given in {@link AcmeRetryAfterException#getRetryAfter()}
     *             before trying again.
     */
    public X509Certificate[] downloadChain() throws AcmeException {
        if (chain == null) {
            if (chainCertUrl == null) {
                download();
            }

            if (chainCertUrl == null) {
                throw new AcmeProtocolException("No certificate chain provided");
            }

            LOG.debug("downloadChain");

            List<X509Certificate> certChain = new ArrayList<>();
            URL link = chainCertUrl;
            while (link != null && certChain.size() < MAX_CHAIN_LENGTH) {
                try (Connection conn = getSession().provider().connect()) {
                    conn.sendRequest(chainCertUrl, getSession());
                    conn.accept(HttpURLConnection.HTTP_OK);

                    certChain.add(conn.readCertificate());
                    link = conn.getLink("up");
                }
            }
            if (link != null) {
                throw new AcmeProtocolException("Recursion limit reached (" + MAX_CHAIN_LENGTH
                    + "). Didn't get " + link);
            }

            chain = certChain.toArray(new X509Certificate[certChain.size()]);
        }
        return chain;
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

        if (cert == null) {
            download();
        }

        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource(Resource.REVOKE_CERT);
            claims.putBase64("certificate", cert.getEncoded());
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
     * Revoke a certificate. This call is meant to be used for revoking certificates if
     * the account's key pair was lost.
     *
     * @param session
     *            {@link Session} to be used. Here you can also generate a session by
     *            using the key pair that was used for signing the CSR.
     * @param cert
     *            {@link X509Certificate} to be revoked
     * @param reason
     *            {@link RevocationReason} stating the reason of the revocation that is
     *            used when generating OCSP responses and CRLs. {@code null} to give no
     *            reason.
     */
    public static void revoke(Session session, X509Certificate cert,
            RevocationReason reason) throws AcmeException {
        try {
            URL dummyUrl = new URL("http://");
            new Certificate(session, dummyUrl, null, cert).revoke(reason);
        } catch (MalformedURLException ex) {
            throw new InternalError(ex);
        }
    }

}
