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
package org.shredzone.acme4j.it;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;

import org.junit.Test;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Tests the complete process of ordering a certificate.
 */
public class OrderIT extends AbstractPebbleIT {

    @Test
    public void testOrder() throws AcmeException, IOException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Registration reg = new RegistrationBuilder().agreeToTermsOfService().create(session);

        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(Duration.ofDays(20L));

        Order order = reg.orderCertificate(csr, notBefore, notAfter);
        assertThat(order.getCsr(), is(csr));
        assertThat(order.getNotBefore(), is(notBefore));
        assertThat(order.getNotAfter(), is(notAfter));
        assertThat(order.getStatus(), is(Status.PENDING));

        for (Authorization auth : order.getAuthorizations()) {
            processAuthorization(auth);
        }
    }

    private void processAuthorization(Authorization auth) throws AcmeException {
        assertThat(auth.getDomain(), is("example.com"));
        if (auth.getStatus() == Status.PENDING) {
            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            assertThat(challenge, is(notNullValue()));
            challenge.trigger();
        }
    }

}
