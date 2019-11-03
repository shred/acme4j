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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.URI;
import java.security.PublicKey;
import java.util.Collections;

import org.junit.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.MockCertificateAuthority;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.AccountController;
import org.shredzone.acme4j.mock.controller.AccountOrdersController;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link MockAccount}.
 */
public class MockAccountTest {
    private static final PublicKey PUBLIC_KEY = KeyPairUtils.createKeyPair(1024).getPublic();

    /**
     * Test creation and default values.
     */
    @Test
    public void testCreate() {
        Repository repository = new Repository();
        MockAccount account = MockAccount.create(repository, PUBLIC_KEY);

        // Check locations
        assertThat(account.getUniqueId(), not(emptyOrNullString()));
        assertThat(account.getLocation().toString(),
                is("https://acme.test/account/" + account.getUniqueId()));
        assertThat(account.getOrdersLocation().toString(),
                is("https://acme.test/account/" + account.getUniqueId() + "/orders"));

        // Controllers were added to the repository?
        assertThat(repository.getController(account.getLocation()).get(),
                is(instanceOf(AccountController.class)));
        assertThat(repository.getController(account.getOrdersLocation()).get(),
                is(instanceOf(AccountOrdersController.class)));
        assertThat(repository.getResourceOfType(account.getLocation(), MockAccount.class).get(),
                is(sameInstance(account)));

        // Default values
        assertThat(account.getContacts(), is(empty()));
        assertThat(account.getExternalAccountBinding(), is(nullValue()));
        assertThat(account.getOrder(), is(empty()));
        assertThat(account.getPublicKey(), is(PUBLIC_KEY));
        assertThat(account.getStatus(), is(Status.VALID));
        assertThat(account.getTermsOfServiceAgreed(), is(nullValue()));

        // Detach from repository
        account.detach(repository);
        assertThat(repository.getController(account.getLocation()).isPresent(),
                is(false));
        assertThat(repository.getController(account.getOrdersLocation()).isPresent(),
                is(false));
        assertThat(repository.getResourceOfType(account.getLocation(), MockAccount.class).isPresent(),
                is(false));
    }

    /**
     * Test setters and JSON generation.
     */
    @Test
    public void testSettersAndJson() {
        Repository repository = new Repository();
        MockCertificateAuthority mockCa = new MockCertificateAuthority();
        MockOrder order = MockOrder.create(repository,
                Collections.singleton(Identifier.dns("example.com")),
                Collections.emptyList(),
                mockCa);
        URI mailto = URI.create("mailto:acme@example.com");
        MockAccount account = MockAccount.create(repository, PUBLIC_KEY);

        account.setStatus(Status.REVOKED);
        account.setTermsOfServiceAgreed(true);
        account.setExternalAccountBinding(JSON.empty());
        account.getContacts().add(mailto);
        account.getOrder().add(order);

        assertThat(account.getStatus(), is(Status.REVOKED));
        assertThat(account.getTermsOfServiceAgreed(), is(true));
        assertThat(account.getExternalAccountBinding().toString(), sameJSONAs("{}"));
        assertThat(account.getContacts(), contains(mailto));
        assertThat(account.getOrder(), contains(order));

        JSONBuilder jb = new JSONBuilder();
        jb.put("status", "revoked");
        jb.array("contact", Collections.singleton(mailto));
        jb.put("termsOfServiceAgreed", true);
        jb.object("externalAccountBinding"); // empty
        jb.put("orders", account.getOrdersLocation());
        assertThat(account.toJSON().toString(), sameJSONAs(jb.toString()));
    }

    /**
     * Test automatic status.
     */
    @Test
    public void testAutoStatus() {
        Repository repository = new Repository();
        MockAccount account = MockAccount.create(repository, PUBLIC_KEY);

        assertThat(account.getStatus(), is(Status.VALID));

        account.setTermsOfServiceAgreed(false);
        assertThat(account.getStatus(), is(Status.REVOKED));

        account.setStatus(Status.UNKNOWN);
        assertThat(account.getStatus(), is(Status.UNKNOWN));
    }

    /**
     * Test key change.
     */
    @Test
    public void testKeyChange() {
        PublicKey replacementKey = KeyPairUtils.createKeyPair(1024).getPublic();

        Repository repository = new Repository();
        MockAccount account = MockAccount.create(repository, PUBLIC_KEY);

        assertThat(account.getPublicKey(), is(PUBLIC_KEY));
        account.setPublicKey(replacementKey);
        assertThat(account.getPublicKey(), is(replacementKey));
    }

}