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

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.it.BammBammClient;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Tests a complete certificate order with different challenges.
 */
public class OrderTlsSniIT {

    private static final String TEST_DOMAIN = "example.com";

    private final String bammbammUrl = System.getProperty("bammbammUrl", "http://localhost:14001");

    private BammBammClient client = new BammBammClient(bammbammUrl);

    /**
     * Test if a certificate can be ordered via http-01 challenge.
     */
    @Test
    public void testHttpValidation() throws Exception {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(boulderURI(), keyPair);

        Account account = new AccountBuilder()
                    .agreeToTermsOfService()
                    .create(session);

        KeyPair domainKeyPair = createKeyPair();

        Order order = account.newOrder().domain(TEST_DOMAIN).create();

        for (Authorization auth : order.getAuthorizations()) {
            TlsSni02Challenge challenge = auth.findChallenge(TlsSni02Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));

            KeyPair challengeKeyPair = createKeyPair();
            X509Certificate challengeCert = CertificateUtils.createTlsSni02Certificate(challengeKeyPair, challenge.getSubject(), challenge.getSanB());

            client.tlsSniAddCertificate(challenge.getSubject(), challengeKeyPair.getPrivate(), challengeCert);

            challenge.trigger();

            await()
                .pollInterval(1, SECONDS)
                .timeout(30, SECONDS)
                .conditionEvaluationListener(cond -> updateAuth(auth))
                .until(auth::getStatus, not(isOneOf(Status.PENDING, Status.PROCESSING)));

            if (auth.getStatus() != Status.VALID) {
                fail("Authorization failed");
            }

            client.tlsSniRemoveCertificate(challenge.getSubject());
        }

        CSRBuilder csr = new CSRBuilder();
        csr.addDomain(TEST_DOMAIN);
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
        assertThat(cert.getSubjectX500Principal().getName(), containsString("CN=" + TEST_DOMAIN));
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

    /**
     * Safely updates the authorization, catching checked exceptions.
     *
     * @param auth
     *            {@link Authorization} to update
     */
    private void updateAuth(Authorization auth) {
        try {
            auth.update();
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(auth, ex);
        }
    }

    /**
     * Safely updates the order, catching checked exceptions.
     *
     * @param order
     *            {@link Order} to update
     */
    private void updateOrder(Order order) {
        try {
            order.update();
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(order, ex);
        }
    }

}
