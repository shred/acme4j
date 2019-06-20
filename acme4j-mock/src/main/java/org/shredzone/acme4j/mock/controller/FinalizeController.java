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
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles order finalizations.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class FinalizeController implements Controller {
    private final MockOrder order;

    /**
     * Creates a new {@link FinalizeController}.
     *
     * @param order
     *         {@link MockOrder} that is to be finalized
     */
    public FinalizeController(MockOrder order) {
        this.order = order;
    }

    /**
     * Finalizes the order.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) {
        byte[] csr = payload.get("csr").asBinary();
        order.setCertificateSigningRequest(csr);
        order.issueCertificate();
        return new Result(order);
    }

}
