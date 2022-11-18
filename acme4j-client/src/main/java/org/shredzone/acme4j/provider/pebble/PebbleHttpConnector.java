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
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;

/**
 * {@link HttpConnector} to be used for Pebble. Pebble uses a static, self signed SSL
 * certificate.
 */
public class PebbleHttpConnector extends HttpConnector {
    private static @Nullable SSLSocketFactory sslSocketFactory = null;

    @Override
    public HttpURLConnection openConnection(URL url, NetworkSettings settings) throws IOException {
        var conn = super.openConnection(url, settings);
        if (conn instanceof HttpsURLConnection) {
            var conns = (HttpsURLConnection) conn;
            conns.setSSLSocketFactory(createSocketFactory());
            conns.setHostnameVerifier((h, s) -> true);
        }
        return conn;
    }

    /**
     * Lazily creates an {@link SSLSocketFactory} that exclusively accepts the Pebble
     * certificate.
     */
    protected synchronized SSLSocketFactory createSocketFactory() throws IOException {
        if (sslSocketFactory == null) {
            try (var in = getClass().getResourceAsStream("/org/shredzone/acme4j/provider/pebble/pebble.truststore")) {
                var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(in, "acme4j".toCharArray());

                var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keystore);

                var ctx = SSLContext.getInstance("TLS");
                ctx.init(null, tmf.getTrustManagers(), null);

                sslSocketFactory = ctx.getSocketFactory();
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
                            | KeyManagementException ex) {
                throw new IOException("Could not create truststore", ex);
            }
        }
        return Objects.requireNonNull(sslSocketFactory);
    }

}
