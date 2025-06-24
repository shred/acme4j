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
package org.shredzone.acme4j.it.pebble;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.DnsAccount01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;

/**
 * Tests a complete certificate order with different challenges.
 */
public class OrderIT extends PebbleITBase {

    private static final String TEST_DOMAIN = "example.com";
    private static final Duration TIMEOUT = Duration.ofSeconds(30L);

    /**
     * Test if a certificate can be ordered via http-01 challenge.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"default", "shortlived"})
    public void testHttpValidation(String profile) throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(Http01Challenge.class).orElseThrow();

            client.httpAddToken(challenge.getToken(), challenge.getAuthorization());

            cleanup(() -> client.httpRemoveToken(challenge.getToken()));

            return challenge;
        }, OrderIT::standardRevoker, profile);
    }

    /**
     * Test if a certificate can be ordered via dns-01 challenge.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"default", "shortlived"})
    public void testDnsValidation(String profile) throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(Dns01Challenge.class).orElseThrow();

            var challengeDomainName = challenge.getRRName(auth.getIdentifier());

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());

            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            return challenge;
        }, OrderIT::standardRevoker, profile);
    }

    /**
     * Test if a certificate can be ordered via dns-account-01 challenge.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"default", "shortlived"})
    @Disabled("Waiting for https://github.com/letsencrypt/pebble/pull/489")
    public void testDnsAccountValidation(String profile) throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(DnsAccount01Challenge.class).orElseThrow();

            var challengeDomainName = challenge.getRRName(auth.getIdentifier());

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());

            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            return challenge;
        }, OrderIT::standardRevoker, profile);
    }

    /**
     * Test if a certificate can be ordered via tns-alpn-01 challenge.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"default", "shortlived"})
    public void testTlsAlpnValidation(String profile) throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(TlsAlpn01Challenge.class).orElseThrow();

            client.tlsAlpnAddCertificate(
                        auth.getIdentifier().getDomain(),
                        challenge.getAuthorization());

            cleanup(() -> client.tlsAlpnRemoveCertificate(auth.getIdentifier().getDomain()));

            return challenge;
        }, OrderIT::standardRevoker, profile);
    }

    /**
     * Test if a certificate can be revoked by its domain key.
     */
    @Test
    public void testDomainKeyRevocation() throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(Http01Challenge.class).orElseThrow();

            client.httpAddToken(challenge.getToken(), challenge.getAuthorization());

            cleanup(() -> client.httpRemoveToken(challenge.getToken()));

            return challenge;
        }, OrderIT::domainKeyRevoker, null);
    }

    /**
     * Runs the complete process of ordering a certificate.
     *
     * @param domain
     *            Name of the domain to order a certificate for
     * @param validator
     *            {@link Validator} that finds and prepares a {@link Challenge} for domain
     *            validation
     * @param revoker
     *            {@link Revoker} that finally revokes the certificate
     * @param profile
     *            Profile to be used, or {@code null} for no profile selection.
     */
    private void orderCertificate(String domain, Validator validator, Revoker revoker, String profile)
            throws Exception {
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        var account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        var domainKeyPair = createKeyPair();

        var notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var notAfter = notBefore.plus(Duration.ofDays(20L));

        var orderBuilder = account.newOrder()
                .domain(domain)
                .notBefore(notBefore)
                .notAfter(notAfter);

        if (profile != null) {
            orderBuilder.profile(profile);
        }

        var order = orderBuilder.create();
        assertThat(order.getNotBefore().orElseThrow()).isEqualTo(notBefore);
        assertThat(order.getNotAfter().orElseThrow()).isEqualTo(notAfter);
        assertThat(order.getStatus()).isEqualTo(Status.PENDING);

        if (profile != null) {
            assertThat(order.getProfile()).contains(profile);
        } else {
            // FIXME: Pebble falls back to different values here, cannot be tested properly
        }

        for (var auth : order.getAuthorizations()) {
            assertThat(auth.getIdentifier().getDomain()).isEqualTo(domain);
            assertThat(auth.getStatus()).isEqualTo(Status.PENDING);

            if (auth.getStatus() == Status.VALID) {
                continue;
            }

            var challenge = validator.prepare(auth);
            challenge.trigger();

            challenge.waitForCompletion(TIMEOUT);

            assertThat(challenge.getStatus()).isEqualTo(Status.VALID);

            auth.fetch();
            assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        }

        order.waitUntilReady(TIMEOUT);
        assertThat(order.getStatus()).isEqualTo(Status.READY);

        order.execute(domainKeyPair);

        order.waitForCompletion(TIMEOUT);
        assertThat(order.getStatus()).isEqualTo(Status.VALID);

        var certificate = order.getCertificate();
        var cert = certificate.getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getNotBefore().toInstant()).isEqualTo(notBefore);
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(notAfter);

        for (var auth :  order.getAuthorizations()) {
            assertThat(auth.getStatus()).isEqualTo(Status.VALID);
            auth.deactivate();
            assertThat(auth.getStatus()).isEqualTo(Status.DEACTIVATED);
        }

        revoker.revoke(session, certificate, keyPair, domainKeyPair);

        /* FIXME: Waiting for https://github.com/letsencrypt/pebble/pull/505 to be deployed
        var ex2 = assertThrows(AcmeServerException.class,
                certificate::revoke,
                "Could revoke again");
        assertThat(ex2.getProblem().getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:alreadyRevoked"));
        */
    }

    /**
     * Revokes a certificate by calling {@link Certificate#revoke(RevocationReason)}.
     * This is the standard way to revoke a certificate.
     */
    private static void standardRevoker(ISession ISession, Certificate certificate,
                                        KeyPair keyPair, KeyPair domainKeyPair) throws Exception {
        certificate.revoke(RevocationReason.KEY_COMPROMISE);
    }

    /**
     * Revokes a certificate by calling
     * {@link Certificate#revoke(ISession, KeyPair, X509Certificate, RevocationReason)}.
     * This way can be used when the account key was lost.
     */
    private static void domainKeyRevoker(ISession ISession, Certificate certificate,
                                         KeyPair keyPair, KeyPair domainKeyPair) throws Exception {
        Certificate.revoke(ISession, domainKeyPair, certificate.getCertificate(),
                RevocationReason.KEY_COMPROMISE);
    }

    @FunctionalInterface
    private interface Validator {
        Challenge prepare(Authorization auth) throws Exception;
    }

    @FunctionalInterface
    private interface Revoker {
        void revoke(ISession ISession, Certificate certificate, KeyPair keyPair,
                    KeyPair domainKeyPair) throws Exception;
    }

}
