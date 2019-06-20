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
package org.shredzone.acme4j.mock.model;

import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;

import org.junit.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.MockCertificateAuthority;
import org.shredzone.acme4j.mock.connection.ProblemBuilder;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.OrderController;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link MockOrder}.
 */
public class MockOrderTest {
    private static final Identifier IDENTIFIER = Identifier.dns("example.org");
    private static final Identifier IDENTIFIER2 = Identifier.dns("www.example.org");

    /**
     * Test creation and default values.
     */
    @Test
    public void testCreate() {
        Repository repository = new Repository();
        MockAuthorization authz = MockAuthorization.create(repository, IDENTIFIER);
        MockCertificateAuthority mockCa = new MockCertificateAuthority();
        MockOrder order = MockOrder.create(repository, singleton(IDENTIFIER), singleton(authz), mockCa);

        // Check locations
        assertThat(order.getUniqueId(), not(emptyOrNullString()));
        assertThat(order.getLocation().toString(),
                is("https://acme.test/order/" + order.getUniqueId()));
        assertThat(order.getFinalizeLocation().toString(),
                is("https://acme.test/order/" + order.getUniqueId() + "/finalize"));
        assertThat(order.getCertificateLocation().toString(),
                is("https://acme.test/certificate/" + order.getUniqueId()));

        // Controllers were added to the repository?
        assertThat(repository.getController(order.getLocation()).get(),
                is(instanceOf(OrderController.class)));
        assertThat(repository.getResourceOfType(order.getLocation(), MockOrder.class).get(),
                is(sameInstance(order)));

        // Default values
        assertThat(order.getAuthorizations(), contains(authz));
        assertThat(order.getCertificate(), is(nullValue()));
        assertThat(order.getCertificateSigningRequest(), is(nullValue()));
        assertThat(order.getError(), is(nullValue()));
        assertThat(order.getExpires(), is(nullValue()));
        assertThat(order.getNotBefore(), is(nullValue()));
        assertThat(order.getNotAfter(), is(nullValue()));
        assertThat(order.getStatus(), is(Status.PENDING));
    }

    /**
     * Test setters and JSON generation.
     */
    @Test
    public void testSettersAndJson() {
        Repository repository = new Repository();
        MockAuthorization authz = MockAuthorization.create(repository, IDENTIFIER);
        MockAuthorization authz2 = MockAuthorization.create(repository, IDENTIFIER2);
        MockCertificateAuthority mockCa = new MockCertificateAuthority();
        MockOrder order = MockOrder.create(repository, asList(IDENTIFIER, IDENTIFIER2),
                asList(authz, authz2), mockCa);

        Problem problem = new ProblemBuilder(order.getLocation())
                .error("badCSR")
                .detail("Key too short")
                .build();
        Instant expires = Instant.now().plus(10, ChronoUnit.DAYS);
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(90, ChronoUnit.DAYS);
        byte[] csr = new byte[321];
        new Random().nextBytes(csr);
        X509Certificate cert = mock(X509Certificate.class);

        order.setStatus(Status.INVALID);
        order.setError(problem);
        order.setCertificateSigningRequest(csr);
        order.setExpires(expires);
        order.setNotBefore(notBefore);
        order.setNotAfter(notAfter);
        order.getAuthorizations().remove(authz2);

        assertThat(order.getStatus(), is(Status.INVALID));
        assertThat(order.getError(), is(problem));
        assertThat(order.getCertificateSigningRequest(), is(csr));
        assertThat(order.getExpires(), is(expires));
        assertThat(order.getNotBefore(), is(notBefore));
        assertThat(order.getNotAfter(),is(notAfter));
        assertThat(order.getAuthorizations(), contains(authz));

        JSONBuilder jb = new JSONBuilder();
        jb.put("status", "invalid");
        jb.put("expires", expires);
        jb.array("identifiers", asList(IDENTIFIER.toMap(), IDENTIFIER2.toMap()));
        jb.put("notBefore", notBefore);
        jb.put("notAfter", notAfter);
        jb.put("error", problem.asJSON().toMap());
        jb.array("authorizations", singleton(authz.getLocation()));
        jb.put("finalize", order.getFinalizeLocation());
        assertThat(order.toJSON().toString(), sameJSONAs(jb.toString()));

        // certificate must only be present if a certificate is available
        order.setCertificate(singletonList(cert));
        assertThat(order.getCertificate(), contains(cert));
        jb.put("certificate", order.getCertificateLocation());
        assertThat(order.toJSON().toString(), sameJSONAs(jb.toString()));
    }

    /**
     * Test automatic status.
     */
    @Test
    public void testAutoStatus() {
        Repository repository = new Repository();
        MockAuthorization authz = MockAuthorization.create(repository, IDENTIFIER);
        MockCertificateAuthority mockCa = new MockCertificateAuthority();
        MockOrder order = MockOrder.create(repository, singleton(IDENTIFIER), singleton(authz), mockCa);

        assertThat(order.getStatus(), is(Status.PENDING));

        order.setError(new ProblemBuilder(order.getLocation()).error("badCSR").build());
        assertThat(order.getStatus(), is(Status.INVALID));
        order.setError(null);

        order.setCertificate(emptyList());
        assertThat(order.getStatus(), is(Status.VALID));
        order.setCertificate(null);

        order.setCertificateSigningRequest(new byte[123]);
        assertThat(order.getStatus(), is(Status.PROCESSING));
        order.setCertificateSigningRequest(null);

        assertThat(order.getStatus(), is(Status.PENDING));
        authz.setStatus(Status.VALID);
        assertThat(order.getStatus(), is(Status.READY));
        authz.setStatus(Status.INVALID);
        assertThat(order.getStatus(), is(Status.INVALID));

        order.setStatus(Status.UNKNOWN);
        assertThat(order.getStatus(), is(Status.UNKNOWN));
    }

}