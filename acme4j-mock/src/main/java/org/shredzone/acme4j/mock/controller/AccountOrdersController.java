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

import static java.util.stream.Collectors.toList;

import java.net.URL;
import java.security.PublicKey;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.mock.model.MockOrder;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A {@link Controller} that lists all orders known to an account.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class AccountOrdersController implements Controller {
    private final MockAccount account;

    /**
     * Creates a new {@link AccountOrdersController}.
     *
     * @param account
     *         {@link MockAccount} to get the list of orders from
     */
    public AccountOrdersController(MockAccount account) {
        this.account = account;
    }

    /**
     * Returns a list of {@link URL} of all orders of this account.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey) {
        JSONBuilder jb = new JSONBuilder();
        jb.array("orders", account.getOrder().stream()
                .map(MockOrder::getLocation)
                .collect(toList())
        );
        return new Result(jb.toJSON());
    }

}
