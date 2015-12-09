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
package org.shredzone.acme4j.provider;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.impl.GenericAcmeClient;

/**
 * An {@link AcmeClientProvider} for <em>Let's Encrypt</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://letsencrypt.org"} for the production server, and
 * {@code "acme://letsencrypt.org/staging"} for a testing server.
 * <p>
 * If you want to use <em>Let's Encrypt</em>, always prefer to use this provider, as it
 * takes care for the correct connection and SSL certificates.
 *
 * @author Richard "Shred" Körber
 * @see <a href="https://letsencrypt.org/">Let's Encrypt</a>
 */
public class LetsEncryptAcmeClientProvider extends AbstractAcmeClientProvider {

    private static final String V01_DIRECTORY_URI = "https://acme-v01.api.letsencrypt.org/directory";
    private static final String STAGING_DIRECTORY_URI = "https://acme-staging.api.letsencrypt.org/directory";

    private SSLSocketFactory sslSocketFactory;

    @Override
    public boolean accepts(String serverUri) {
        return serverUri.startsWith("acme://letsencrypt.org");
    }

    @Override
    public AcmeClient connect(String serverUri) {
        String directoryUri;
        switch (serverUri) {
            case "acme://letsencrypt.org/staging":
                directoryUri = STAGING_DIRECTORY_URI;
                break;

            case "acme://letsencrypt.org/v01":
            case "acme://letsencrypt.org":
                directoryUri = V01_DIRECTORY_URI;
                break;

            default:
                throw new IllegalArgumentException("Unknown URI " + serverUri);
        }

        try {
            return new GenericAcmeClient(this, new URI(directoryUri));
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException(directoryUri, ex);
        }
    }

    @Override
    public HttpURLConnection openConnection(URI uri) throws IOException {
        HttpURLConnection conn = super.openConnection(uri);
        if (conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(createSocketFactory());
        }
        return conn;
    }

    /**
     * Lazily creates an {@link SSLSocketFactory} that exclusively accepts the Let's
     * Encrypt certificate.
     */
    private SSLSocketFactory createSocketFactory() throws IOException {
        if (sslSocketFactory == null) {
            try {
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(getClass().getResourceAsStream("/org/shredzone/acme4j/letsencrypt.truststore"),
                                "acme4j".toCharArray());

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keystore);

                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, tmf.getTrustManagers(), null);

                sslSocketFactory = ctx.getSocketFactory();
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
                            | KeyManagementException ex) {
                throw new IOException("Could not create truststore", ex);
            }
        }
        return sslSocketFactory;
    }

}
