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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate and its certificate chain.
 */
public class Certificate extends AcmeResource {
    private static final long serialVersionUID = 7381527770159084201L;
    private static final Logger LOG = LoggerFactory.getLogger(Certificate.class);
    private static final int MAX_CHAIN_LENGTH = 10;

    private URI chainCertUri;
    private X509Certificate cert = null;
    private X509Certificate[] chain = null;

    /**
     * Creates a new instance of {@link Certificate} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location of the Certificate
     */
    public static Certificate bind(Session session, URI location) {
        return new Certificate(session, location);
    }

    protected Certificate(Session session, URI certUri) {
        super(session);
        setLocation(certUri);
    }

    protected Certificate(Session session, URI certUri, URI chainUri, X509Certificate cert) {
        super(session);
        setLocation(certUri);
        this.chainCertUri = chainUri;
        this.cert = cert;
    }

    /**
     * Returns the URI of the certificate chain. {@code null} if not known or not
     * available.
     */
    public URI getChainLocation() {
        return chainCertUri;
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
                int rc = conn.sendRequest(getLocation(), getSession());
                if (rc == HttpURLConnection.HTTP_ACCEPTED) {
                    Date retryAfter = conn.getRetryAfterHeader();
                    if (retryAfter != null) {
                        throw new AcmeRetryAfterException(
                                        "certificate is not available for download yet",
                                        retryAfter);
                    }
                }

                if (rc != HttpURLConnection.HTTP_OK) {
                    conn.throwAcmeException();
                }

                chainCertUri = conn.getLink("up");
                cert = conn.readCertificate();
            } catch (IOException ex) {
                throw new AcmeNetworkException(ex);
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
            if (chainCertUri == null) {
                download();
            }

            if (chainCertUri == null) {
                throw new AcmeProtocolException("No certificate chain provided");
            }

            LOG.debug("downloadChain");

            List<X509Certificate> certChain = new ArrayList<>();
            URI link = chainCertUri;
            while (link != null && certChain.size() < MAX_CHAIN_LENGTH) {
                try (Connection conn = getSession().provider().connect()) {
                    int rc = conn.sendRequest(chainCertUri, getSession());
                    if (rc != HttpURLConnection.HTTP_OK) {
                        conn.throwAcmeException();
                    }

                    certChain.add(conn.readCertificate());
                    link = conn.getLink("up");
                } catch (IOException ex) {
                    throw new AcmeNetworkException(ex);
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
        URI resUri = getSession().resourceUri(Resource.REVOKE_CERT);
        if (resUri == null) {
            throw new AcmeProtocolException("CA does not support certificate revocation");
        }

        if (cert == null) {
            download();
        }

        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.REVOKE_CERT);
            claims.putBase64("certificate", cert.getEncoded());
            if (reason != null) {
                claims.put("reason", reason.getReasonCode());
            }

            int rc = conn.sendSignedRequest(resUri, claims, getSession());
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (CertificateEncodingException ex) {
            throw new AcmeProtocolException("Invalid certificate", ex);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

}
