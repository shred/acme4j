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
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;

/**
 * {@link HttpConnector} to be used for Pebble. Pebble uses a static, self-signed SSL
 * certificate.
 */
public class PebbleHttpConnector extends HttpConnector {
    private static final AtomicReference<SSLContext> SSL_CONTEXT_REF = new AtomicReference<>();

    public PebbleHttpConnector(NetworkSettings settings) {
        super(settings);
    }

    @Override
    public HttpClient.Builder createClientBuilder() {
        var builder = super.createClientBuilder();
        builder.sslContext(createSSLContext());
        return builder;
    }

    /**
     * Lazily creates an {@link SSLContext} that exclusively accepts the Pebble
     * certificate.
     */
    protected SSLContext createSSLContext() {
        if (SSL_CONTEXT_REF.get() == null) {
            try (var in = getClass().getResourceAsStream("/org/shredzone/acme4j/provider/pebble/pebble.truststore")) {
                var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(in, "acme4j".toCharArray());

                var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keystore);

                var sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, tmf.getTrustManagers(), null);
                SSL_CONTEXT_REF.set(sslContext);
            } catch (IOException | KeyStoreException | CertificateException
                     | NoSuchAlgorithmException | KeyManagementException ex) {
                throw new RuntimeException("Could not create truststore", ex);
            }
        }
        return Objects.requireNonNull(SSL_CONTEXT_REF.get());
    }

}
