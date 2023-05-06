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
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
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
        var client = getBammBammClient();
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        var account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        var domainKeyPair = createKeyPair();

        var notBefore = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        var notAfter = notBefore.plus(Duration.ofDays(20L));

        var order = account.newOrder()
                    .domain(TEST_WILDCARD_DOMAIN)
                    .domain(TEST_DOMAIN)
                    .notBefore(notBefore)
                    .notAfter(notAfter)
                    .create();
        assertThat(order.getNotBefore().orElseThrow()).isEqualTo(notBefore);
        assertThat(order.getNotAfter().orElseThrow()).isEqualTo(notAfter);
        assertThat(order.getStatus()).isEqualTo(Status.PENDING);

        for (var auth : order.getAuthorizations()) {
            assertThat(auth.getIdentifier().getDomain()).isEqualTo(TEST_DOMAIN);
            assertThat(auth.getStatus()).isEqualTo(Status.PENDING);

            if (auth.getStatus() == Status.VALID) {
                continue;
            }

            var challenge = auth.findChallenge(Dns01Challenge.class).orElseThrow();

            var challengeDomainName = Dns01Challenge.toRRName(TEST_DOMAIN);

            client.dnsAddTxtRecord(challengeDomainName, challenge.getDigest());
            cleanup(() -> client.dnsRemoveTxtRecord(challengeDomainName));

            challenge.trigger();

            await()
                .pollInterval(1, SECONDS)
                .timeout(30, SECONDS)
                .conditionEvaluationListener(cond -> updateAuth(auth))
                .untilAsserted(() -> assertThat(
                        auth.getStatus()).isNotIn(Status.PENDING, Status.PROCESSING));

            assertThat(auth.getStatus()).isEqualTo(Status.VALID);
        }

        var csr = new CSRBuilder();
        csr.addDomain(TEST_DOMAIN);
        csr.addDomain(TEST_WILDCARD_DOMAIN);
        csr.sign(domainKeyPair);
        var encodedCsr = csr.getEncoded();

        order.execute(encodedCsr);

        await()
            .pollInterval(1, SECONDS)
            .timeout(30, SECONDS)
            .conditionEvaluationListener(cond -> updateOrder(order))
            .untilAsserted(() -> assertThat(
                    order.getStatus()).isNotIn(Status.PENDING, Status.PROCESSING));


        var cert = order.getCertificate().getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getNotAfter()).isNotEqualTo(notBefore);
        assertThat(cert.getNotBefore()).isNotEqualTo(notAfter);
        assertThat(cert.getSubjectX500Principal().getName()).contains("CN=" + TEST_DOMAIN);

        var san = cert.getSubjectAlternativeNames().stream()
                .filter(it -> ((Number) it.get(0)).intValue() == GeneralName.dNSName)
                .map(it -> (String) it.get(1))
                .collect(toList());
        assertThat(san).contains(TEST_DOMAIN, TEST_WILDCARD_DOMAIN);
    }

}
