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
package org.shredzone.acme4j.it.boulder;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.security.KeyPair;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.it.BammBammClient;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Tests a complete certificate order with different challenges.
 */
public class OrderHttpIT {

    private static final String TEST_DOMAIN = "example.com";
    private static final Duration TIMEOUT = Duration.ofSeconds(30L);

    private final String bammbammUrl = System.getProperty("bammbammUrl", "http://localhost:14001");

    private final BammBammClient client = new BammBammClient(bammbammUrl);

    /**
     * Test if a certificate can be ordered via http-01 challenge.
     */
    @Test
    public void testHttpValidation() throws Exception {
        var session = new Session(boulderURI());
        var keyPair = createKeyPair();

        var account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        var domainKeyPair = createKeyPair();

        var order = account.newOrder().domain(TEST_DOMAIN).create();

        for (var auth : order.getAuthorizations()) {
            var challenge = auth.findChallenge(Http01Challenge.class).orElseThrow();

            client.httpAddToken(challenge.getToken(), challenge.getAuthorization());

            challenge.trigger();
            challenge.waitForCompletion(TIMEOUT);

            assertThat(challenge.getStatus()).isEqualTo(Status.VALID);
            assertThat(auth.getStatus()).isEqualTo(Status.VALID);

            client.httpRemoveToken(challenge.getToken());
        }

        order.waitUntilReady(TIMEOUT);
        assertThat(order.getStatus()).isEqualTo(Status.READY);

        order.execute(domainKeyPair);
        order.waitForCompletion(TIMEOUT);
        assertThat(order.getStatus()).isEqualTo(Status.VALID);

        var cert = order.getCertificate().getCertificate();
        assertThat(cert.getNotAfter()).isNotNull();
        assertThat(cert.getNotBefore()).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("CN=" + TEST_DOMAIN);
    }

    /**
     * @return The {@link URI} of the Boulder server to test against.
     */
    protected URI boulderURI() {
        return URI.create("http://localhost:4001/directory");
    }

    /**
     * Creates a fresh key pair.
     *
     * @return Created new {@link KeyPair}
     */
    protected KeyPair createKeyPair() {
        return KeyPairUtils.createKeyPair(2048);
    }

}
