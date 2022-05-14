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
import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.it.BammBammClient;
import org.shredzone.acme4j.util.CSRBuilder;

/**
 * Tests a complete wildcard certificate order. Wildcard certificates currently only
 * support dns-01 challenge.
 */
public class OrderWildcardIT extends PebbleITBase {

    private static final String TEST_DOMAIN = "example.com";
    private static final String TEST_WILDCARD_DOMAIN = "*.example.com";

    /**
     * Test if a wildcard certificate can be ordered via dns-01 challenge.
     */
    @Test
    public void testDnsValidation() throws Exception {
        BammBammClient client = getBammBammClient();
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        Account account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        KeyPair domainKeyPair = createKeyPair();

        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant notAfter = notBefore.plus(Duration.ofDays(20L));

        Order order = account.newOrder()
                    .domain(TEST_WILDCARD_DOMAIN)
                    .domain(TEST_DOMAIN)
                    .notBefore(notBefore)
                    .notAfter(notAfter)
                    .create();
        assertThat(order.getNotBefore(), is(notBefore));
        assertThat(order.getNotAfter(), is(notAfter));
        assertThat(order.getStatus(), is(Status.PENDING));

        for (Authorization auth : order.getAuthorizations()) {
            assertThat(auth.getIdentifier().getDomain(), is(TEST_DOMAIN));
            assertThat(auth.getStatus(), is(Status.PENDING));

            if (auth.getStatus() == Status.VALID) {
                continue;
            }

            Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

            String challengeDomainName = "_acme-challenge." + TEST_DOMAIN;

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());
            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            challenge.trigger();

            await()
                .pollInterval(1, SECONDS)
                .timeout(30, SECONDS)
                .conditionEvaluationListener(cond -> updateAuth(auth))
                .until(auth::getStatus, not(oneOf(Status.PENDING, Status.PROCESSING)));

            assertThat(auth.getStatus(), is(Status.VALID));
        }

        CSRBuilder csr = new CSRBuilder();
        csr.addDomain(TEST_DOMAIN);
        csr.addDomain(TEST_WILDCARD_DOMAIN);
        csr.sign(domainKeyPair);
        byte[] encodedCsr = csr.getEncoded();

        order.execute(encodedCsr);

        await()
            .pollInterval(1, SECONDS)
            .timeout(30, SECONDS)
            .conditionEvaluationListener(cond -> updateOrder(order))
            .until(order::getStatus, not(oneOf(Status.PENDING, Status.PROCESSING)));


        Certificate certificate = order.getCertificate();
        X509Certificate cert = certificate.getCertificate();
        assertThat(cert, not(nullValue()));
        assertThat(cert.getNotAfter(), not(notBefore));
        assertThat(cert.getNotBefore(), not(notAfter));
        assertThat(cert.getSubjectX500Principal().getName(), containsString("CN=" + TEST_DOMAIN));

        List<String> san = cert.getSubjectAlternativeNames().stream()
                .filter(it -> ((Number) it.get(0)).intValue() == GeneralName.dNSName)
                .map(it -> (String) it.get(1))
                .collect(toList());
        assertThat(san, contains(TEST_DOMAIN, TEST_WILDCARD_DOMAIN));
    }

}
