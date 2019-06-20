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

import org.shredzone.acme4j.mock.MockAcmeServer;

/**
 * A {@link Controller} that handles newNonce requests. The mock server takes care about
 * nonces already, so this controller is actually doing nothing at all. It is just here
 * because the "newNonce" endpoint is required.
 * <p>
 * Note that wrapping this controller is rather useless, as the controller is never
 * invoked.
 *
 * @since 2.8
 */
public class NewNonceController implements Controller {

    /**
     * Creates a new {@link NewNonceController}.
     *
     * @param server
     *         {@link MockAcmeServer} that manages the nonces
     */
    public NewNonceController(MockAcmeServer server) {
        // intentionally left blank
    }

}
