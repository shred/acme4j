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
import java.util.List;
import java.util.Optional;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that processes {@code newAccount} requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class NewAccountController implements Controller {
    private final MockAcmeServer server;

    /**
     * Creates a new {@link NewAccountController}.
     *
     * @param server
     *         {@link MockAcmeServer} that is used for creating new accounts
     */
    public NewAccountController(MockAcmeServer server) {
        this.server = server;
    }

    /**
     * Creates a new account.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) throws AcmeException {
        Optional<MockAccount> existingAccount = server.findAccount(publicKey);

        if (existingAccount.isPresent()) {
            return new Result(existingAccount.get());
        }

        if (payload.contains("onlyReturnExisting") && payload.get("onlyReturnExisting").asBoolean()) {
            throw MockError.accountDoesNotExist(requestUrl);
        }

        MockAccount account = server.createAccount(publicKey);

        if (payload.contains("contact")) {
            List<URI> contactList = account.getContacts();
            payload.get("contact").asArray().stream()
                    .map(JSON.Value::asURI)
                    .forEach(contactList::add);
        }

        payload.get("termsOfServiceAgreed").optional()
                .map(JSON.Value::asBoolean)
                .ifPresent(account::setTermsOfServiceAgreed);

        payload.get("externalAccountBinding").optional()
                .map(JSON.Value::asObject)
                .ifPresent(account::setExternalAccountBinding);

        return new Result(account);
    }

}
