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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link AcmeProvider} for <em>Pebble</em>.
 * <p>
 * <a href="https://github.com/letsencrypt/pebble">Pebble</a> is a small ACME test server.
 * This provider can be used to connect to an instance of a Pebble server.
 * <p>
 * {@code "acme://pebble"} connects to a Pebble server running on localhost and listening
 * on the standard port 14000. Using {@code "acme://pebble/other-host:12345"}, it is
 * possible to connect to an external Pebble server on the given {@code other-host} and
 * port. The port is optional, and if omitted, the standard port is used.
 */
public class PebbleAcmeProvider extends AbstractAcmeProvider {
    private static final Logger LOG = LoggerFactory.getLogger(PebbleAcmeProvider.class);
    private static final Pattern HOST_PATTERN = Pattern.compile("^/([^:/]+)(?:\\:(\\d+))?/?$");
    private static final int PEBBLE_DEFAULT_PORT = 14000;

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme()) && "pebble".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        try {
            var path = serverUri.getPath();
            int port = serverUri.getPort() != -1 ? serverUri.getPort() : PEBBLE_DEFAULT_PORT;

            var baseUrl = URI.create("https://localhost:" + port + "/dir").toURL();

            if (path != null && !path.isEmpty() && !"/".equals(path)) {
                baseUrl = parsePath(path);
            }

            return baseUrl;
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Bad server URI " + serverUri, ex);
        }
    }

    /**
     * Parses the server URI path and returns the server's base URL.
     *
     * @param path
     *            server URI path
     * @return URL of the server's base
     */
    private URL parsePath(String path) throws MalformedURLException {
        var m = HOST_PATTERN.matcher(path);
        if (m.matches()) {
            var host = m.group(1);
            var port = PEBBLE_DEFAULT_PORT;
            if (m.group(2) != null) {
                port = Integer.parseInt(m.group(2));
            }
            try {
                return new URI("https", null, host, port, "/dir", null, null).toURL();
            } catch (URISyntaxException ex) {
                throw new IllegalArgumentException("Malformed Pebble host/port: " + path);
            }
        } else {
            throw new IllegalArgumentException("Invalid Pebble host/port: " + path);
        }
    }

    @Override
    public HttpClient createHttpClient(NetworkSettings networkSettings) {
        var builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(networkSettings.getTimeout())
                .proxy(networkSettings.getProxySelector())
                .sslContext(createPebbleSSLContext());

        if (networkSettings.getAuthenticator() != null) {
            builder.authenticator(networkSettings.getAuthenticator());
        }

        return builder.build();
    }

    /**
     * Creates a TrustManagerFactory configured with the Pebble root certificate.
     * <p>
     * This method loads the Pebble root certificate from the PEM file and creates
     * a TrustManagerFactory that trusts certificates signed by Pebble's CA.
     *
     * @return TrustManagerFactory configured for Pebble
     * @throws RuntimeException if the Pebble certificate cannot be found or loaded
     * @since 4.0.0
     */
    protected TrustManagerFactory createPebbleTrustManagerFactory() {
        try {
            var keystore = readPemFile("/pebble.minica.pem")
                    .or(() -> readPemFile("/META-INF/pebble.minica.pem"))
                    .or(() -> readPemFile("/org/shredzone/acme4j/provider/pebble/pebble.minica.pem"))
                    .orElseThrow(() -> new RuntimeException("Could not find a Pebble root certificate"));

            var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keystore);
            return tmf;
        } catch (KeyStoreException | NoSuchAlgorithmException ex) {
            throw new RuntimeException("Could not create truststore", ex);
        }
    }

    /**
     * Creates the Pebble SSL context.
     * <p>
     * Since the HTTP client is cached at the session level, this method is only called
     * once per session, so no additional caching is needed.
     *
     * @return SSLContext configured for Pebble
     */
    private SSLContext createPebbleSSLContext() {
        try {
            var tmf = createPebbleTrustManagerFactory();

            var sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new RuntimeException("Could not create SSL context", ex);
        }
    }

    /**
     * Reads a PEM file from a resource for Pebble SSL context creation.
     */
    private Optional<KeyStore> readPemFile(String resource) {
        try (var in = PebbleAcmeProvider.class.getResourceAsStream(resource)) {
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
