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
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

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
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
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

            client.dnsAddARecord(TEST_DOMAIN, getBammBammHostname());
            client.httpAddToken(challenge.getToken(), challenge.getAuthorization());

            cleanup(() -> client.dnsRemoveARecord(TEST_DOMAIN));
            cleanup(() -> client.httpRemoveToken(challenge.getToken()));

            return challenge;
        });
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

            String challengeDomainName = "_acme-challenge." + TEST_DOMAIN;

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());

            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            return challenge;
        });
    }

    /**
     * Runs the complete process of ordering a certificate.
     *
     * @param domain
     *            Name of the domain to order a certificate for
     * @param validator
     *            {@link Validator} that finds and prepares a {@link Challenge} for domain
     *            validation
     */
    private void orderCertificate(String domain, Validator validator) throws Exception {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Account account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .create(session);

        KeyPair domainKeyPair = createKeyPair();

        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.MILLIS);
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
            assertThat(auth.getDomain(), is(domain));
            assertThat(auth.getStatus(), is(Status.PENDING));

            Challenge challenge = validator.prepare(auth);
            challenge.trigger();

            await()
                .pollInterval(1, SECONDS)
                .timeout(30, SECONDS)
                .conditionEvaluationListener(cond -> updateAuth(auth))
                .until(auth::getStatus, not(isOneOf(Status.PENDING, Status.PROCESSING)));

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
            .until(order::getStatus, not(isOneOf(Status.PENDING, Status.PROCESSING)));


        Certificate certificate = order.getCertificate();
        X509Certificate cert = certificate.getCertificate();
        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), not(nullValue()));
        assertThat(cert.getNotBefore(), not(nullValue()));
        assertThat(cert.getSubjectX500Principal().getName(), containsString("CN=" + domain));
    }

    @FunctionalInterface
    private static interface Validator {
        Challenge prepare(Authorization auth) throws Exception;
    }

}
