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

import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JoseUtils;

/**
 * A {@link Controller} that handles key change requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class KeyChangeController implements Controller {
    private final MockAcmeServer server;

    /**
     * Creates a new {@link KeyChangeController}.
     *
     * @param server
     *         {@link MockAcmeServer} that is managing the accounts
     */
    public KeyChangeController(MockAcmeServer server) {
        this.server = server;
    }

    /**
     * Changes an account key after validation.
     *
     * @param requestUrl
     *         Request {@link URL}
     * @param payload
     *         Payload containing an inner payload with the account's location and the
     *         old key, which is signed by the new key.
     * @param publicKey
     *         The current account key.
     * @return Empty result
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) throws AcmeException {
        JSON innerPayload = payload.get("payload").asEncodedObject();
        JSON innerProtected = payload.get("protected").asEncodedObject();

        URL accountLocation = innerPayload.get("account").asURL();
        PublicKey oldKey = JoseUtils.jwkToPublicKey(innerPayload.get("oldKey").asObject().toMap());
        PublicKey newKey = JoseUtils.jwkToPublicKey(innerProtected.get("jwk").asObject().toMap());

        Optional<MockAccount> optAccount = server.findAccount(oldKey);
        if (!optAccount.isPresent()) {
            throw MockError.accountDoesNotExist(requestUrl);
        }
        MockAccount account = optAccount.get();

        if (!Arrays.equals(publicKey.getEncoded(), oldKey.getEncoded())) {
            throw MockError.problem(requestUrl, "malformed", "wrong account key");
        }

        try {
            if (!account.getLocation().toURI().equals(accountLocation.toURI())) {
                throw MockError.problem(requestUrl, "malformed", "account location URL mismatch");
            }
        } catch (URISyntaxException ex) {
            throw new IllegalStateException(ex);
        }

        Optional<MockAccount> conflictingAccount = server.findAccount(newKey);
        if (conflictingAccount.isPresent()) {
            throw MockError.httpError(HttpURLConnection.HTTP_CONFLICT, "conflicting account");
        }

        account.setPublicKey(newKey);
        return Result.empty();
    }

}
