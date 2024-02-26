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
import java.net.URL;

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
     * Test Let's Encrypt
     */
    @Test
    public void testLetsEncrypt() throws AcmeException, MalformedURLException {
        var session = new Session("acme://letsencrypt.org");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://letsencrypt.org"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();

        var sessionStage = new Session("acme://letsencrypt.org/staging");
        assertThat(sessionStage.getMetadata().getWebsite()).hasValue(new URL("https://letsencrypt.org/docs/staging-environment/"));
        assertThatNoException().isThrownBy(() -> sessionStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionStage.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(sessionStage.getMetadata().isAutoRenewalEnabled()).isFalse();
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
    }

    /**
     * Test ssl.com
     */
    @Test
    public void testSslCom() throws AcmeException, MalformedURLException {
        var session = new Session("acme://ssl.com");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();

        var sessionStage = new Session("acme://ssl.com/staging");
        assertThat(sessionStage.getMetadata().getWebsite()).hasValue(new URL("https://www.ssl.com"));
        assertThatNoException().isThrownBy(() -> sessionStage.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(sessionStage.getMetadata().isExternalAccountRequired()).isFalse();
        assertThat(sessionStage.getMetadata().isAutoRenewalEnabled()).isFalse();
    }

    /**
     * Test ZeroSSL
     */
    @Test
    public void testZeroSsl() throws AcmeException, MalformedURLException {
        var session = new Session("acme://zerossl.com");
        assertThat(session.getMetadata().getWebsite()).hasValue(new URL("https://zerossl.com"));
        assertThatNoException().isThrownBy(() -> session.resourceUrl(Resource.NEW_ACCOUNT));
        assertThat(session.getMetadata().isExternalAccountRequired()).isTrue();
        assertThat(session.getMetadata().isAutoRenewalEnabled()).isFalse();

        // ZeroSSL has no documented staging server (as of February 2024)
    }

}
