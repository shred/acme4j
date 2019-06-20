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

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAuthorization;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles newAuthz requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class NewAuthzController implements Controller {
    private final MockAcmeServer server;

    /**
     * Creates a new {@link NewAuthzController}.
     *
     * @param server
     *         {@link MockAcmeServer} that manages authorizations
     */
    public NewAuthzController(MockAcmeServer server) {
        this.server = server;
    }

    /**
     * Creates a new authorization and returns it.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) {
        Identifier identifier = payload.get("identifier").asIdentifier();
        MockAuthorization auth = server.createAuthorization(identifier);
        return new Result(auth);
    }

}
