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

import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles certificate revocations.
 *
 * @since 2.8
 */
public class RevokeCertController implements Controller {

    /**
     * Creates a new {@link RevokeCertController}.
     *
     * @param server
     *         {@link MockAcmeServer} that is used
     */
    public RevokeCertController(MockAcmeServer server) {
        // intentionally left blank
    }

    /**
     * Revokes a certificate.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) {
        // There is no ACME server feedback on certificate revocation
        return Result.empty();
    }

}
