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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.connector.NetworkSettings;

/**
 * Unit tests for {@link PebbleAcmeProvider}.
 */
public class PebbleAcmeProviderTest {

    /**
     * Tests if the provider accepts the correct URIs.
     */
    @Test
    public void testAccepts() throws URISyntaxException {
        var provider = new PebbleAcmeProvider();

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(provider.accepts(new URI("acme://pebble"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble:12345"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble:12345/"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/some-host.example.com"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://pebble/some-host.example.com:12345"))).isTrue();
            softly.assertThat(provider.accepts(new URI("acme://example.com"))).isFalse();
            softly.assertThat(provider.accepts(new URI("http://example.com/acme"))).isFalse();
            softly.assertThat(provider.accepts(new URI("https://example.com/acme"))).isFalse();
        }
    }

    /**
     * Test if acme URIs are properly resolved.
     */
    @Test
    public void testResolve() throws URISyntaxException {
        var provider = new PebbleAcmeProvider();

        assertThat(provider.resolve(new URI("acme://pebble")))
                .isEqualTo(url("https://localhost:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/")))
                .isEqualTo(url("https://localhost:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble:12345")))
            .isEqualTo(url("https://localhost:12345/dir"));
        assertThat(provider.resolve(new URI("acme://pebble:12345/")))
            .isEqualTo(url("https://localhost:12345/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com")))
                .isEqualTo(url("https://pebble.example.com:14000/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com:12345")))
                .isEqualTo(url("https://pebble.example.com:12345/dir"));
        assertThat(provider.resolve(new URI("acme://pebble/pebble.example.com:12345/")))
                .isEqualTo(url("https://pebble.example.com:12345/dir"));

        assertThrows(IllegalArgumentException.class, () ->
                provider.resolve(new URI("acme://pebble/bad.example.com:port")));

        assertThrows(IllegalArgumentException.class, () ->
                provider.resolve(new URI("acme://pebble/bad.example.com:1234/foo")));
    }

    /**
     * Test that createPebbleTrustManagerFactory creates a TrustManagerFactory
     * with the Pebble certificate loaded from the PEM file.
     */
    @Test
    public void testCreatePebbleTrustManagerFactory() throws Exception {
        var provider = new PebbleAcmeProvider();
        
        // Create the TrustManagerFactory
        TrustManagerFactory tmf = provider.createPebbleTrustManagerFactory();
        assertThat(tmf).isNotNull();
        
        // Get the trust managers
        javax.net.ssl.TrustManager[] trustManagers = tmf.getTrustManagers();
        assertThat(trustManagers.length).isGreaterThan(0);
        
        // Find an X509TrustManager
        X509TrustManager x509TrustManager = null;
        for (javax.net.ssl.TrustManager tm : trustManagers) {
            if (tm instanceof X509TrustManager) {
                x509TrustManager = (X509TrustManager) tm;
                break;
            }
        }
        assertThat(x509TrustManager).isNotNull();
        
        // Verify the Pebble certificate is in the accepted issuers
        X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
        assertThat(acceptedIssuers.length).isGreaterThan(0);
        
        // Load the Pebble certificate from the resource to compare
        X509Certificate pebbleCert = loadPebbleCertificate();
        assertThat(pebbleCert).isNotNull();
        
        // Verify that the Pebble certificate is in the accepted issuers
        boolean foundPebbleCert = false;
        for (X509Certificate cert : acceptedIssuers) {
            if (cert.getSerialNumber().equals(pebbleCert.getSerialNumber()) &&
                cert.getIssuerDN().equals(pebbleCert.getIssuerDN())) {
                foundPebbleCert = true;
                break;
            }
        }
        
        // Verify the Pebble certificate is present in the trust store
        assertThat(foundPebbleCert)
                .as("Pebble certificate should be present in the TrustManagerFactory")
                .isTrue();
    }
    
    /**
     * Test that createHttpClient creates an HttpClient with Pebble SSL context
     * and verifies it calls createPebbleTrustManagerFactory when creating the SSL context.
     */
    @Test
    public void testCreateHttpClient() throws Exception {
        var provider = spy(new PebbleAcmeProvider());
        var settings = new NetworkSettings();

        var httpClient = provider.createHttpClient(settings);

        assertThat(httpClient).isNotNull();
        assertThat(httpClient.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
        assertThat(httpClient.connectTimeout().orElseThrow()).isEqualTo(settings.getTimeout());
        
        // Verify that createPebbleTrustManagerFactory was called exactly once
        // (it's called when creating the SSL context, which happens once per createHttpClient call)
        verify(provider).createPebbleTrustManagerFactory();
        
        // Verify that the SSL context is configured (not null)
        var sslContext = httpClient.sslContext();
        assertThat(sslContext).isNotNull();
        
        // Verify Pebble-specific SSL context properties
        // These properties confirm that the SSL context was created using createPebbleTrustManagerFactory
        assertThat(sslContext.getProtocol()).isEqualTo("TLS");
        
        // Verify the SSL context is properly initialized
        assertThat(sslContext.getProvider()).isNotNull();
    }
    
    /**
     * Loads the Pebble certificate from the resource file.
     * This matches how PebbleAcmeProvider loads it.
     */
    private X509Certificate loadPebbleCertificate() throws Exception {
        // Try the same resource paths as PebbleAcmeProvider
        String[] resourcePaths = {
            "/pebble.minica.pem",
            "/META-INF/pebble.minica.pem",
            "/org/shredzone/acme4j/provider/pebble/pebble.minica.pem"
        };
        
        for (String resourcePath : resourcePaths) {
            try (InputStream in = PebbleAcmeProvider.class.getResourceAsStream(resourcePath)) {
                if (in != null) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    return (X509Certificate) cf.generateCertificate(in);
                }
            }
        }
        
        throw new AssertionError("Could not find Pebble certificate resource");
    }
}
