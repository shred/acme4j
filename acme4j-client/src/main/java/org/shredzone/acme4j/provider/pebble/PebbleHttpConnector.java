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
import java.security.cert.CertificateFactory;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link HttpConnector} to be used for Pebble. Pebble uses a static, self-signed SSL
 * certificate.
 */
public class PebbleHttpConnector extends HttpConnector {
    private static final Logger LOG = LoggerFactory.getLogger(PebbleHttpConnector.class);
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
            try {
                var keystore = readPemFile("/pebble.minica.pem")
                        .or(() -> readPemFile("/META-INF/pebble.minica.pem"))
                        .or(() -> readPemFile("/org/shredzone/acme4j/provider/pebble/pebble.minica.pem"))
                        .orElseThrow(() -> new RuntimeException("Could not find a Pebble root certificate"));

                var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keystore);

                var sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, tmf.getTrustManagers(), null);
                SSL_CONTEXT_REF.set(sslContext);
            } catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException ex) {
                throw new RuntimeException("Could not create truststore", ex);
            }
        }
        return Objects.requireNonNull(SSL_CONTEXT_REF.get());
    }

    /**
     * Reads a PEM file from a resource, and returns a {@link KeyStore} that uses this
     * certificate as root CA.
     *
     * @param resource
     *         Resource name
     * @return A {@link KeyStore} if the resource could be read successfully, otherwise
     * empty.
     */
    private Optional<KeyStore> readPemFile(String resource) {
        try (var in = getClass().getResourceAsStream(resource)) {
            if (in == null) {
                return Optional.empty();
            }
            var cf = CertificateFactory.getInstance("X.509");
            var cert = cf.generateCertificate(in);
            var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(null, "acme4j".toCharArray());
            keystore.setCertificateEntry("pebble", cert);
            return Optional.of(keystore);
        } catch (IOException | KeyStoreException | CertificateException
                 | NoSuchAlgorithmException ex) {
            LOG.error("Failed to read PEM from resource '{}'", resource, ex);
            return Optional.empty();
        }
    }

}
