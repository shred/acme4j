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

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.fail;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.RevocationReason;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.it.BammBammClient;
import org.shredzone.acme4j.util.CSRBuilder;

/**
 * Tests a complete certificate order with different challenges.
 */
public class OrderIT extends PebbleITBase {

    private static final String TEST_DOMAIN = "example.com";

    /**
     * Test if a certificate can be ordered via http-01 challenge.
     */
    @Test
    public void testHttpValidation() throws Exception {
        orderCertificate(TEST_DOMAIN, auth -> {
            BammBammClient client = getBammBammClient();

            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

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
            BammBammClient client = getBammBammClient();

            Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

            String challengeDomainName = "_acme-challenge." + auth.getIdentifier().getDomain();

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
            BammBammClient client = getBammBammClient();

            TlsAlpn01Challenge challenge = auth.findChallenge(TlsAlpn01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

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
            BammBammClient client = getBammBammClient();

            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

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
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        Account account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        KeyPair domainKeyPair = createKeyPair();

        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant notAfter = notBefore.plus(Duration.ofDays(20L));

        Order order = account.newOrder()
                    .domain(domain)
                    .notBefore(notBefore)
                    .notAfter(notAfter)
                    .create();
        assertThat(order.getNotBefore(), is(notBefore));
        assertThat(order.getNotAfter(), is(notAfter));
        assertThat(order.getStatus(), is(Status.PENDING));

        for (Authorization auth : order.getAuthorizations()) {
            assertThat(auth.getIdentifier().getDomain(), is(domain));
            assertThat(auth.getStatus(), is(Status.PENDING));

            if (auth.getStatus() == Status.VALID) {
                continue;
            }

            Challenge challenge = validator.prepare(auth);
            challenge.trigger();

            await()
                .pollInterval(1, SECONDS)
                .timeout(30, SECONDS)
                .conditionEvaluationListener(cond -> updateAuth(auth))
                .until(auth::getStatus, not(oneOf(Status.PENDING, Status.PROCESSING)));

            if (auth.getStatus() != Status.VALID) {
                fail("Authorization failed");
            }
        }

        CSRBuilder csr = new CSRBuilder();
        csr.addDomain(domain);
        csr.sign(domainKeyPair);
        byte[] encodedCsr = csr.getEncoded();

        order.execute(encodedCsr);

        await()
            .pollInterval(1, SECONDS)
            .timeout(30, SECONDS)
            .conditionEvaluationListener(cond -> updateOrder(order))
            .until(order::getStatus, not(oneOf(Status.PENDING, Status.PROCESSING, Status.READY)));

        if (order.getStatus() != Status.VALID) {
            fail("Order failed");
        }

        Certificate certificate = order.getCertificate();
        X509Certificate cert = certificate.getCertificate();
        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotBefore().toInstant(), is(notBefore));
        assertThat(cert.getNotAfter().toInstant(), is(notAfter));
        assertThat(cert.getSubjectX500Principal().getName(), containsString("CN=" + domain));

        for (Authorization auth :  order.getAuthorizations()) {
            assertThat(auth.getStatus(), is(Status.VALID));
            auth.deactivate();
            assertThat(auth.getStatus(), is(Status.DEACTIVATED));
        }

        revoker.revoke(session, certificate, keyPair, domainKeyPair);

        // Make sure certificate is revoked
        try {
            Login login2 = session.login(account.getLocation(), keyPair);
            Certificate cert2 = login2.bindCertificate(certificate.getLocation());
            cert2.download();
            fail("Could download revoked cert");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), is("HTTP 404: Not Found"));
        }

        // Try to revoke again
        try {
            certificate.revoke();
            fail("Could revoke again");
        } catch (AcmeServerException ex) {
            assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:alreadyRevoked")));
        }
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
