/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.challenge;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge.
 */
@ParametersAreNonnullByDefault
public class Http01Challenge extends TokenChallenge {
    private static final long serialVersionUID = 3322211185872544605L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "http-01";

    /**
     * Creates a new generic {@link Http01Challenge} object.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param data
     *            {@link JSON} challenge data
     */
    public Http01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Returns the token to be used for this challenge.
     */
    @Override
    public String getToken() {
        return super.getToken();
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
