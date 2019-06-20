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

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Processes an ACME request to a defined {@link URL} and gives a {@link Result}.
 * <p>
 * By default, all methods throw a 405 "Method Not Allowed" error.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public interface Controller {

    /**
     * Processes a simple and unauthorized GET request.
     *
     * @param requestUrl
     *         Request {@link URL}
     * @return {@link Result} to be returned to the client
     */
    default Result doSimpleRequest(URL requestUrl) throws AcmeException {
        throw MockError.methodNotAllowed();
    }

    /**
     * Processes an authorized POST-as-GET request.
     *
     * @param requestUrl
     *         Request {@link URL}
     * @param publicKey
     *         The account's public key the request is signed with
     * @return {@link Result} to be returned to the client
     */
    default Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey)
            throws AcmeException {
        throw MockError.methodNotAllowed();
    }

    /**
     * Processes an authorized POST request.
     *
     * @param requestUrl
     *         Request {@link URL}
     * @param payload
     *         {@link JSON} payload that was POSTed to the ACME server
     * @param publicKey
     *         The account's public key the request is signed with
     * @return {@link Result} to be returned to the client
     */
    default Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey)
            throws AcmeException {
        throw MockError.methodNotAllowed();
    }

}
