/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A provider that creates a Challenge from a matching JSON.
 *
 * @since 2.12
 */
@FunctionalInterface
public interface ChallengeProvider {

    /**
     * Creates a Challenge.
     *
     * @param login
     *         {@link Login} of the user's account
     * @param data
     *         {@link JSON} of the challenge as sent by the CA
     * @return Created and initialized {@link Challenge}. It must match the JSON type.
     */
    Challenge create(Login login, JSON data);

}
