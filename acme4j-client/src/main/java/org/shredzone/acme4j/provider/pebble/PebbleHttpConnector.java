/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider.pebble;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.HttpConnector;

/**
 * {@link HttpConnector} to be used for Pebble. Pebble uses a static, self signed SSL
 * certificate.
 */
@ParametersAreNonnullByDefault
@ThreadSafe
public class PebbleHttpConnector extends HttpConnector {

    private static HostnameVerifier ALLOW_ALL_HOSTNAME_VERIFIER = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    private static SSLSocketFactory sslSocketFactory;

    @Override
    public HttpURLConnection openConnection(URL url, Proxy proxy) throws IOException {
        HttpURLConnection conn = super.openConnection(url, proxy);
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection conns = (HttpsURLConnection) conn;
            conns.setSSLSocketFactory(createSocketFactory());
            conns.setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER);
        }
        return conn;
    }

    /**
     * Lazily creates an {@link SSLSocketFactory} that exclusively accepts the Pebble
     * certificate.
     */
    protected synchronized SSLSocketFactory createSocketFactory() throws IOException {
        if (sslSocketFactory == null) {
            try (InputStream in = getClass().getResourceAsStream("/org/shredzone/acme4j/provider/pebble/pebble.truststore")) {
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(in, "acme4j".toCharArray());

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
