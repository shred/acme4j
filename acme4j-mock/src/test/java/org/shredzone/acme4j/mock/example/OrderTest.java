/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.example;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.MockCertificateAuthority;
import org.shredzone.acme4j.mock.model.MockAuthorization;
import org.shredzone.acme4j.mock.model.MockChallenge;
import org.shredzone.acme4j.mock.model.MockOrder;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * This unit test simulates a certificate order, starting at account creation and ending
 * at certificate download.
 * <p>
 * This example shows that the mock server is designed to simulate a real ACME workflow.
 * There is no need for much interaction with the mock server to test a successful
 * certificate generation.
 */
public class OrderTest {

    @Test
    public void testCreateOrder() throws AcmeException, IOException {
        MockAcmeServer server = new MockAcmeServer();

        // Create a new empty account and get a Login
        Login login = server.createLogin();
        Account account = login.getAccount();

        // Order a certificate for "example.org"
        Order order = account.newOrder()
                .domain("example.org")
                .create();

        // Order status is PENDING by default
        assertThat(order.getStatus(), is(Status.PENDING));

        // Offer a http-01 and dns-01 challenge for each authorization
        MockOrder mockOrder = server.getMockOf(order);
        for (MockAuthorization mockAuthorization : mockOrder.getAuthorizations()) {
            List<MockChallenge> mockChallenges = mockAuthorization.getChallenges();
            mockChallenges.add(server.createChallenge(Http01Challenge.TYPE));
            mockChallenges.add(server.createChallenge(Dns01Challenge.TYPE));
        }

        // Let the client find and process all http-01 challenge
        for (Authorization auth : order.getAuthorizations()) {
            Http01Challenge challenge = auth.findChallenge(Http01Challenge.class);
            assertThat(challenge, is(notNullValue()));

            // This would be the moment where the client prepares to respond
            // to the challenge...

            // Challenge is currently pending
            assertThat(challenge.getStatus(), is(Status.PENDING));

            // Start it... The mock server will simulate a successful validation.
            challenge.trigger();

            // Challenge status has changed to VALID
            challenge.update();
            assertThat(challenge.getStatus(), is(Status.VALID));

            // Authorization status is now also VALID
            auth.update();
            assertThat(auth.getStatus(), is(Status.VALID));
        }

        // All authorizations are valid now. Order status is READY.
        order.update();
        assertThat(order.getStatus(), is(Status.READY));

        // Finalize the order
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);
        CSRBuilder csrb = new CSRBuilder();
        csrb.addIdentifiers(order.getIdentifiers());
        csrb.sign(domainKeyPair);
        order.execute(csrb.getEncoded());

        // Order is ready now
        order.update();
        assertThat(order.getStatus(), is(Status.VALID));

        // Download the certificate
        Certificate certificate = order.getCertificate();
        assertThat(certificate, not(nullValue()));

        // Validate the certificate
        MockCertificateAuthority mockCa = server.getCertificateAuthority();
        List<X509Certificate> certChain = certificate.getCertificateChain();
        assertThat(certChain.size(), is(3));
        mockCa.assertValidCertificate(certChain.get(0));
        assertThat(certChain.get(1), is(mockCa.getIntermediateCertificate()));
        assertThat(certChain.get(2), is(mockCa.getRootCertificate()));
    }

}
