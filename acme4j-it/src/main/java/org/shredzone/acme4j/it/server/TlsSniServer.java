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
package org.shredzone.acme4j.it.server;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A very simple TnsSni server. It waits for a connection and performs a TLS handshake
 * returning the matching certificate to the requested domain.
 * <p>
 * This server can be used to validate {@code tls-sni-02} challenges.
 */
public class TlsSniServer {
    private static final Logger LOG = LoggerFactory.getLogger(TlsSniServer.class);
    private static final char[] PASSWORD = "shibboleet".toCharArray();

    private KeyStore keyStore = null;
    private Thread thread = null;
    private volatile boolean running = false;
    private volatile boolean listening = false;

    /**
     * Adds a certificate to the set of known certificates.
     * <p>
     * The certificate's CN and SANs are used for SNI.
     *
     * @param alias
     *            Internal alias
     * @param privateKey
     *            Private key to be used with this certificate
     * @param cert
     *            {@link X509Certificate} to be added
     */
    public void addCertificate(String alias, PrivateKey privateKey, X509Certificate cert) {
        initKeyStore();

        try {
            keyStore.setKeyEntry(alias, privateKey, PASSWORD, new Certificate[] {cert});
        } catch (KeyStoreException ex) {
            throw new IllegalArgumentException("Failed to add certificate " + alias, ex);
        }
    }

    /**
     * Removes a certificate.
     *
     * @param alias
     *            Internal alias of the certificate to remove
     */
    public void removeCertificate(String alias) {
        initKeyStore();

        try {
            keyStore.deleteEntry(alias);
        } catch (KeyStoreException ex) {
            throw new IllegalArgumentException("Failed to remove certificate " + alias, ex);
        }
    }

    /**
     * Starts the TlsSni server.
     *
     * @param port
     *            Port to listen to
     */
    public void start(int port) {
        if (thread != null) {
            throw new IllegalStateException("Server is already running");
        }

        running = true;
        thread = new Thread(() -> serve(port));
        thread.setName("tls-sni server");
        thread.start();
        LOG.info("tls-sni server listening at port {}", port);
    }

    /**
     * Stops the TlsSni server.
     */
    public void stop() {
        if (thread != null) {
            running = false;
            thread.interrupt();
            thread = null;
        }
    }

    /**
     * Checks if the server was started up and is listening to connections.
     */
    public boolean isListening() {
        return listening;
    }

    /**
     * Opens an SSL server socket and processes incoming requests.
     *
     * @param port
     *            Port to listen at
     */
    private void serve(int port) {
        SSLContext sslContext = createSSLContext();
        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        while (running) {
            try (SSLServerSocket sslServerSocket = (SSLServerSocket)
                            sslServerSocketFactory.createServerSocket(port)){
                listening = true;
                process(sslServerSocket);
            } catch (Exception ex) {
                LOG.error("Failed to process query", ex);
            }
        }

        listening = false;
    }

    /**
     * Accept and process an incoming request. Only the TLS handshake is used here.
     * Incoming data is just consumed, and the socket is closed after that.
     *
     * @param sslServerSocket
     *            {@link SSLServerSocket} to accept connections from
     * @throws IOException
     *             if the request could not be processed
     */
    private void process(SSLServerSocket sslServerSocket) throws IOException {
        try (SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept()) {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
            sslSocket.startHandshake();

            SSLSession sslSession = sslSocket.getSession();
            X509Certificate cert = (X509Certificate) sslSession.getLocalCertificates()[0];
            LOG.info("tls-sni: {}", domainsToString(cert));

            try (InputStream in = sslSocket.getInputStream()) {
                while (in.read() >= 0); //NOSONAR: intentional empty statement
            }
        }
    }

    /**
     * Lazily initializes the {@link KeyStore} instance to be used. The key store is empty
     * after initialization.
     */
    private void initKeyStore() {
        if (keyStore == null) {
            try {
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(null, null);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException
                            | IOException ex) {
                throw new IllegalStateException("Failed to create key store", ex);
            }
        }
    }

    /**
     * Creates a {@link SSLContext} that uses the internal {@link KeyStore} for key and
     * trust management.
     *
     * @return {@link SSLContext} instance
     */
    private SSLContext createSSLContext() {
        initKeyStore();

        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
            keyManagerFactory.init(keyStore, PASSWORD);
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km, tm, null);

            return sslContext;
        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException
                        | UnrecoverableKeyException ex) {
            throw new IllegalStateException("Could not create SSLContext", ex);
        }
    }

    /**
     * Extracts all SANs of the given certificate and returns them as a string.
     *
     * @param cert
     *            {@link X509Certificate} to read the SANs from
     * @return String of all SAN names joined together and separated by comma
     */
    private String domainsToString(X509Certificate cert)  {
        try {
            return cert.getSubjectAlternativeNames().stream()
                .filter(c -> ((Number) c.get(0)).intValue() == GeneralName.dNSName)
                .map(c -> (String) c.get(1))
                .collect(Collectors.joining(", "));
        } catch (CertificateParsingException ex) {
            throw new IllegalArgumentException("bad certificate", ex);
        }
    }

}
