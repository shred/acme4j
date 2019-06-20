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
import java.util.function.Function;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Wraps an existing {@link Controller} instance, so single methods can be intercepted and
 * changed in their behavior.
 * <p>
 * Implementing classes can just extend this wrapper, and override single {@link
 * Controller} methods at will. By default, the {@link Controller} methods just forward to
 * the wrapped controller.
 *
 * @see Repository#wrapController(URL, Function)
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public abstract class ControllerWrapper<C extends Controller> implements Controller {
    private final C receiver;

    /**
     * Creates a new {@link ControllerWrapper}.
     *
     * @param receiver
     *         Receiving {@link Controller} that is being wrapped.
     */
    public ControllerWrapper(C receiver) {
        this.receiver = receiver;
    }

    /**
     * Returns the receiving {@link Controller} instance.
     */
    protected C getController() {
        return receiver;
    }

    @Override
    public Result doSimpleRequest(URL requestUrl) throws AcmeException {
        return getController().doSimpleRequest(requestUrl);
    }

    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey)
            throws AcmeException {
        return getController().doPostAsGetRequest(requestUrl, publicKey);
    }

    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey)
            throws AcmeException {
        return getController().doPostRequest(requestUrl, payload, publicKey);
    }

}
