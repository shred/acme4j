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

import java.net.URI;
import java.net.URL;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.AccountController;
import org.shredzone.acme4j.mock.controller.AccountOrdersController;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A mock account.
 * <p>
 * It reflects the server side of {@link org.shredzone.acme4j.Account} objects.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockAccount extends MockResource {
    private final List<URI> contact = new ArrayList<>();
    private final List<MockOrder> order = new ArrayList<>();

    private PublicKey publicKey;
    private Status status;
    private Boolean termsOfServiceAgreed = null;
    private JSON externalAccountBinding = null;

    /**
     * Internal constructor. Use {@link MockAccount#create(Repository, PublicKey)}.
     */
    private MockAccount(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Creates a new {@link MockAccount} instance.
     *
     * @param repository
     *         {@link Repository} to add the resource to
     * @param publicKey
     *         {@link PublicKey} of the new account
     * @return The generated {@link MockAccount}
     */
    public static MockAccount create(Repository repository, PublicKey publicKey) {
        MockAccount account = new MockAccount(publicKey);
        repository.addResource(account, AccountController::new);
        repository.addController(account.getOrdersLocation(), new AccountOrdersController(account));
        return account;
    }

    /**
     * Returns the public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets a new public key.
     *
     * @param publicKey
     *         new {@link PublicKey}
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Returns the current account status.
     * <p>
     * If no concrete status was set via {@link #setStatus(Status)}, the mock resource
     * tries to deduce a reasonable status from its current state.
     */
    public Status getStatus() {
        if (status != null) {
            return status;
        }

        if (Boolean.FALSE.equals(termsOfServiceAgreed)) {
            return Status.REVOKED;
        }

        return Status.VALID;
    }

    /**
     * Sets the current account status.
     *
     * @param status
     *         new {@link Status}, or {@code null} to clear the status and let the
     *         resource decide on its current status automatically.
     */
    public void setStatus(@Nullable Status status) {
        this.status = status;
    }

    /**
     * Gets the list of contact {@link URI}. This list can be modified.
     */
    public List<URI> getContacts() {
        return contact;
    }

    /**
     * Returns whether the terms of service have been agreed to. May be {@code null}
     * if the state is undefined.
     */
    @CheckForNull
    public Boolean getTermsOfServiceAgreed() {
        return termsOfServiceAgreed;
    }

    /**
     * Sets whether the terms of service have been agreed to.
     *
     * @param termsOfServiceAgreed
     *         Have the terms of service been agreed to? {@code null} if undefined.
     */
    public void setTermsOfServiceAgreed(@Nullable Boolean termsOfServiceAgreed) {
        this.termsOfServiceAgreed = termsOfServiceAgreed;
    }

    /**
     * Returns the external account binding used when setting up the account, or {@code
     * null} if no external account binding was performed.
     */
    @CheckForNull
    public JSON getExternalAccountBinding() {
        return externalAccountBinding;
    }

    /**
     * Sets the external account binding structure.
     *
     * @param externalAccountBinding
     *         External account binding structure, or {@code null} if no external account
     *         binding was performed.
     */
    public void setExternalAccountBinding(@Nullable JSON externalAccountBinding) {
        this.externalAccountBinding = externalAccountBinding;
    }

    /**
     * Returns a list of all {@link MockOrder} related to this account. This list can be
     * modified.
     */
    public List<MockOrder> getOrder() {
        return order;
    }

    @Override
    public URL getLocation() {
        return buildUrl("account", getUniqueId());
    }

    /**
     * Returns the {@link URL} where a list of orders can be retrieved from.
     */
    public URL getOrdersLocation() {
        return buildUrl("account", getUniqueId(), "orders");
    }

    @Override
    public JSON toJSON() {
        JSONBuilder jb = new JSONBuilder();
        jb.put("status", getStatus().name().toLowerCase());
        if (!getContacts().isEmpty()) {
            jb.array("contact", getContacts());
        }
        if (getTermsOfServiceAgreed() != null) {
            jb.put("termsOfServiceAgreed", getTermsOfServiceAgreed());
        }
        JSON eab = getExternalAccountBinding();
        if (eab != null) {
            jb.put("externalAccountBinding", eab.toMap());
        }
        jb.put("orders", getOrdersLocation());
        return jb.toJSON();
    }

}
