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

import java.net.URL;
import java.security.PublicKey;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockOrder;

/**
 * A {@link Controller} that handles order related requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class OrderController implements Controller {
    private final MockOrder order;

    /**
     * Creates a new {@link OrderController}.
     *
     * @param order
     *         {@link MockOrder} this controller is bound to
     */
    public OrderController(MockOrder order) {
        this.order = order;
    }

    /**
     * Just returns the current state of the order.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey) {
        return new Result(order);
    }

}
