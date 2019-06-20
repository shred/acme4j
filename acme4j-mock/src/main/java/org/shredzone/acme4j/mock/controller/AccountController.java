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
package org.shredzone.acme4j.mock.controller;

import java.net.URI;
import java.net.URL;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles account related requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class AccountController implements Controller {
    private final MockAccount account;

    /**
     * Creates a new {@link AccountController}.
     *
     * @param account
     *         {@link MockAccount} this controller is bound to
     */
    public AccountController(MockAccount account) {
        this.account = account;
    }

    /**
     * Just return the current state of the account.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey) {
        return new Result(account);
    }

    /**
     * Modifies the account, then returns the new state.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) throws AcmeException {
        if (!Arrays.equals(account.getPublicKey().getEncoded(), publicKey.getEncoded())) {
            throw MockError.unauthorized(requestUrl);
        }

        if (payload.contains("contact")) {
            List<URI> contacts = account.getContacts();
            contacts.clear();
            payload.get("contact").asArray().stream()
                    .map(JSON.Value::asURI)
                    .forEach(contacts::add);
        }

        if (payload.contains("status")) {
            Status status = payload.get("status").asStatus();
            if (status == Status.DEACTIVATED) {
                account.setStatus(Status.DEACTIVATED);
            }
        }

        return doPostAsGetRequest(requestUrl, publicKey);
    }

}
