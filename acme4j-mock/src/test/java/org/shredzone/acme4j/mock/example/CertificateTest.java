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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.ProblemBuilder;
import org.shredzone.acme4j.mock.model.MockOrder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * This test shows how to prepare a mock server for a unit test.
 * <p>
 * In this example, we are going to test a method that downloads a certificate from a
 * finalized {@link Order}.
 * <p>
 * The first test {@link #testValid()} prepares a mock server that has a valid order and a
 * certificate that is ready for downloading.
 * <p>
 * The second test {@link #testFailure()} also prepares a mock server, but this time it
 * has an order that is invalid because of an error that occured during finalization.
 */
public class CertificateTest {

    /**
     * This is the method to be unit tested. It receives an {@link Order} and downloads
     * the certificate chain.
     *
     * @param order
     *         A valid {@link Order} to download the certificate from
     * @return A list of {@link X509Certificate} that was downloaded
     */
    public List<X509Certificate> downloadCertificate(Order order) {
        if (order.getStatus() != Status.VALID) {
            throw new IllegalStateException("Order is not valid!");
        }

        Certificate certificate = order.getCertificate();
        if (certificate == null) {
            throw new IllegalStateException("No certificate?");
        }
        return certificate.getCertificateChain();
    }

    /**
     * This is a successful test. It sets up a server environment with a completed order,
     * and a certificate that is ready for downloading.
     */
    @Test
    public void testValid() {
        // Set up a mock server. It contains an order that has been completed and
        // has a certificate ready for downloading.
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

        MockAcmeServer server = new MockAcmeServer();
        MockOrder mockOrder = server.createOrder(Identifier.dns("example.com"));
        mockOrder.generateCsr(domainKeyPair);
        mockOrder.issueCertificate();

        // Create a Login and bind the mock order to a real Order resource
        Login login = server.createLogin();
        Order order = login.bindOrder(mockOrder.getLocation());

        // Unit test the method
        List<X509Certificate> certificates = downloadCertificate(order);

        // We got the certificate
        assertThat(certificates.size(), is(3));
        server.getCertificateAuthority().assertValidCertificate(certificates.get(0));
    }

    /**
     * This test checks a failure situation. It sets up a server environment with an order
     * that is invalid due to an error. We expect this test to catch an {@link
     * IllegalStateException} that was thrown by {@link #downloadCertificate(Order)}.
     */
    @Test(expected = IllegalStateException.class)
    public void testFailure() {
        // Set up a mock server and add an order
        MockAcmeServer server = new MockAcmeServer();
        MockOrder mockOrder = server.createOrder(Identifier.dns("example.com"));

        // This time, there was an error
        Problem problem = new ProblemBuilder(mockOrder.getLocation())
                .error("badCSR")
                .detail("Key is too short")
                .build();
        mockOrder.setError(problem);

        // Create a Login and bind the mock order to a real Order resource
        Login login = server.createLogin();
        Order order = login.bindOrder(mockOrder.getLocation());

        // Unit test the method
        // It will throw an IllegalStateException because the order is not valid
        downloadCertificate(order);
    }

}
