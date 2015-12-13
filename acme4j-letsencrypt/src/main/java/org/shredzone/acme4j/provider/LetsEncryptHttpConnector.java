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
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.HttpConnector;

/**
 * {@link HttpConnector} to be used for Let's Encrypt. It is pinned to the Let's Encrypt
 * server certificate.
 *
 * @author Richard "Shred" Körber
 */
public class LetsEncryptHttpConnector extends HttpConnector {

    private SSLSocketFactory sslSocketFactory;

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
    protected SSLSocketFactory createSocketFactory() throws IOException {
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
