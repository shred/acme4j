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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.RevocationReason;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;

/**
 * Tests a complete certificate order with different challenges.
 */
public class OrderIT extends PebbleITBase {

    private static final String TEST_DOMAIN = "example.com";
    private static final Duration TIMEOUT = Duration.ofSeconds(30L);

    /**
     * Test if a certificate can be ordered via http-01 challenge.
     */
    @Test
    public void testHttpValidation() throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(Http01Challenge.class).orElseThrow();

            client.httpAddToken(challenge.getToken(), challenge.getAuthorization());

            cleanup(() -> client.httpRemoveToken(challenge.getToken()));

            return challenge;
        }, OrderIT::standardRevoker);
    }

    /**
     * Test if a certificate can be ordered via dns-01 challenge.
     */
    @Test
    public void testDnsValidation() throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(Dns01Challenge.class).orElseThrow();

            var challengeDomainName = Dns01Challenge.toRRName(auth.getIdentifier());

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());

            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            return challenge;
        }, OrderIT::standardRevoker);
    }

    /**
     * Test if a certificate can be ordered via tns-alpn-01 challenge.
     */
    @Test
    public void testTlsAlpnValidation() throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            var client = getBammBammClient();

            var challenge = auth.findChallenge(TlsAlpn01Challenge.class).orElseThrow();

            client.tlsAlpnAddCertificate(
                        auth.getIdentifier().getDomain(),
                        challenge.getAuthorization());

            cleanup(() -> client.tlsAlpnRemoveCertificate(auth.getIdentifier().getDomain()));

            return challenge;
        }, OrderIT::standardRevoker);
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
        }, OrderIT::domainKeyRevoker);
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
     */
    private void orderCertificate(String domain, Validator validator, Revoker revoker)
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

        var order = account.newOrder()
                    .domain(domain)
                    .notBefore(notBefore)
                    .notAfter(notAfter)
                    .create();
        assertThat(order.getNotBefore().orElseThrow()).isEqualTo(notBefore);
        assertThat(order.getNotAfter().orElseThrow()).isEqualTo(notAfter);
        assertThat(order.getStatus()).isEqualTo(Status.PENDING);

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

        // Make sure certificate is revoked
        var ex = assertThrows(AcmeException.class, () -> {
            Login login2 = session.login(account.getLocation(), keyPair);
            Certificate cert2 = login2.bindCertificate(certificate.getLocation());
            cert2.download();
        }, "Could download revoked cert");
        assertThat(ex.getMessage()).isEqualTo("HTTP 404");

        // Try to revoke again
        var ex2 = assertThrows(AcmeServerException.class,
                certificate::revoke,
                "Could revoke again");
        assertThat(ex2.getProblem().getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:alreadyRevoked"));
    }

    /**
     * Revokes a certificate by calling {@link Certificate#revoke(RevocationReason)}.
     * This is the standard way to revoke a certificate.
     */
    private static void standardRevoker(Session session, Certificate certificate,
            KeyPair keyPair, KeyPair domainKeyPair) throws Exception {
        certificate.revoke(RevocationReason.KEY_COMPROMISE);
    }

    /**
     * Revokes a certificate by calling
     * {@link Certificate#revoke(Session, KeyPair, X509Certificate, RevocationReason)}.
     * This way can be used when the account key was lost.
     */
    private static void domainKeyRevoker(Session session, Certificate certificate,
            KeyPair keyPair, KeyPair domainKeyPair) throws Exception {
        Certificate.revoke(session, domainKeyPair, certificate.getCertificate(),
                RevocationReason.KEY_COMPROMISE);
    }

    @FunctionalInterface
    private interface Validator {
        Challenge prepare(Authorization auth) throws Exception;
    }

    @FunctionalInterface
    private interface Revoker {
        void revoke(Session session, Certificate certificate, KeyPair keyPair,
            KeyPair domainKeyPair) throws Exception;
    }

}
