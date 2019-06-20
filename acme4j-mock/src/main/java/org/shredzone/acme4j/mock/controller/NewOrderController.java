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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.mock.model.MockOrder;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles new order requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class NewOrderController implements Controller {
    private final MockAcmeServer server;

    /**
     * Creates a new {@link NewOrderController}.
     *
     * @param server
     *         {@link MockAcmeServer} that is used for creating new accounts
     */
    public NewOrderController(MockAcmeServer server) {
        this.server = server;
    }

    /**
     * Creates a new order for the identifiers in the payload, and returns the new order.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) throws AcmeException {
        Optional<MockAccount> account = server.findAccount(publicKey);
        if (!account.isPresent()) {
            throw MockError.unauthorized(requestUrl);
        }

        List<Identifier> identifiers = payload.get("identifiers").asArray().stream()
                .map(JSON.Value::asIdentifier)
                .collect(toList());

        MockOrder order = server.createOrder(identifiers);
        order.setExpires(Instant.now().plus(1, ChronoUnit.DAYS));

        if (payload.contains("notBefore")) {
            order.setNotBefore(payload.get("notBefore").asInstant());
        }

        if (payload.contains("notAfter")) {
            order.setNotAfter(payload.get("notAfter").asInstant());
        }

        return new Result(order);
    }

}
