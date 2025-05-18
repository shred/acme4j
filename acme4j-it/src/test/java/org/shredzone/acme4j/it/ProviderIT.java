/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2024 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * A very simple test to check if all provider URIs are still pointing to a directory
 * resource.
 * <p>
 * If one of these tests fails, it could be an indicator that the corresponding directory
 * URL has been changed on CA side, or that EAR or auto-renewal features have been
 * changed.
 * <p>
 * These integration tests require a network connection.
 */
public class ProviderIT {

    /**
     * Test Buypass
     */
    @Test
    public void testBuypass() throws AcmeException, MalformedURLException {
        var session = new Session("acme://buypass.com");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://buypass.com/"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(session.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();

        var sessionStage = new Session("acme://buypass.com/staging");
        assertThat(sessionStage.getMetadata().getWebsite()).hasValue(new URL("https://buypass.com/"));
        assertThatNoException().isThrownBy(() -> sessionStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionStage.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(sessionStage.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionStage.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();
    }

    /**
     * Test Google CA
     */
    @Test
    public void testGoogle() throws AcmeException, MalformedURLException {
        var session = new Session("acme://pki.goog");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://pki.goog"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(session.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();

        var sessionStage = new Session("acme://pki.goog/staging");
        assertThat(sessionStage.getMetadata().getWebsite()).hasValue(new URL("https://pki.goog"));
        assertThatNoException().isThrownBy(() -> sessionStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionStage.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(sessionStage.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionStage.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();
    }

    /**
     * Test Let's Encrypt
     */
    @Test
    public void testLetsEncrypt() throws AcmeException, MalformedURLException {
        var session = new Session("acme://letsencrypt.org");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://letsencrypt.org"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(session.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();

        var sessionStage = new Session("acme://letsencrypt.org/staging");
        assertThat(sessionStage.getMetadata().getWebsite()).hasValue(new URL("https://letsencrypt.org/docs/staging-environment/"));
        assertThatNoException().isThrownBy(() -> sessionStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionStage.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(sessionStage.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionStage.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();
    }

    /**
     * Test Pebble
     */
    @Test
    public void testPebble() throws AcmeException, MalformedURLException {
        var session = new Session("acme://pebble");
        assertThat(session.getMetadata().getWebsite()).isEmpty();
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(session.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();
    }

    /**
     * Test ssl.com, production
     */
    @Test
    public void testSslCom() throws AcmeException, MalformedURLException {
        var sessionEcc = new Session("acme://ssl.com/ecc");
        assertThat(sessionEcc.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> sessionEcc.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionEcc.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(sessionEcc.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionEcc.resourceUrlOptional(Resource.RENEWAL_INFO)).isEmpty();

        var sessionRsa = new Session("acme://ssl.com/rsa");
        assertThat(sessionRsa.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> sessionRsa.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionRsa.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(sessionRsa.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionRsa.resourceUrlOptional(Resource.RENEWAL_INFO)).isEmpty();

        // If this test fails, the metadata has been fixed on server side. Then remove
        // the patch at ZeroSSLAcmeProvider, and update the documentation.
        var sessionEABCheck = new Session("https://acme.ssl.com/sslcom-dv-ecc");
        assertThat(sessionEABCheck.getMetadata().isExternalAccountRequired()).isFalse();
    }

    /**
     * Test ssl.com, staging server
     */
    @Test
    @Disabled("Instable due to frequent certificate expiration of acme-try.ssl.com")
    public void testSslComStaging() throws AcmeException, MalformedURLException {
        var sessionEccStage = new Session("acme://ssl.com/staging/ecc");
        assertThat(sessionEccStage.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> sessionEccStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionEccStage.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(sessionEccStage.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionEccStage.resourceUrlOptional(Resource.RENEWAL_INFO)).isEmpty();

        var sessionRsaStage = new Session("acme://ssl.com/staging/rsa");
        assertThat(sessionRsaStage.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> sessionRsaStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionRsaStage.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(sessionRsaStage.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(sessionRsaStage.resourceUrlOptional(Resource.RENEWAL_INFO)).isEmpty();

        // If this test fails, the metadata has been fixed on server side. Then remove
        // the patch at ZeroSSLAcmeProvider, and update the documentation.
        var sessionEABCheckStage = new Session("https://acme-try.ssl.com/sslcom-dv-ecc");
        assertThat(sessionEABCheckStage.getMetadata().isExternalAccountRequired()).isFalse();
    }

    /**
     * Test ZeroSSL
     */
    @Test
    public void testZeroSsl() throws AcmeException, MalformedURLException {
        var session = new Session("acme://zerossl.com");
        session.networkSettings().setTimeout(Duration.ofSeconds(120L));
        assertThat(session.getMetadata().getWebsite()).hasValue(URI.create("https://zerossl.com").toURL());
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();
        assertThat(session.resourceUrlOptional(Resource.RENEWAL_INFO)).isNotEmpty();

        // ZeroSSL has no documented staging server (as of February 2024)
    }

}
