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

import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockChallenge;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Controller} that handles challenge requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class ChallengeController implements Controller {
    private final MockChallenge challenge;

    /**
     * Creates a new {@link ChallengeController}.
     *
     * @param challenge
     *         {@link MockChallenge} bound to this controller
     */
    public ChallengeController(MockChallenge challenge) {
        this.challenge = challenge;
    }

    /**
     * Returns the current state of the challenge.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey) {
        return new Result(challenge);
    }

    /**
     * Triggers the challenge.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostRequest(URL requestUrl, JSON payload, PublicKey publicKey) {
        if (challenge.getStatus() == Status.PENDING) {
            challenge.setStatus(Status.VALID);
        }
        return new Result(challenge);
    }

}
