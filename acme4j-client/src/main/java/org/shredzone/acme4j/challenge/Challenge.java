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

import java.net.URI;
import java.util.Date;
import java.util.Map;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * A challenge.
 *
 * @author Richard "Shred" Körber
 */
public interface Challenge {

    /**
     * Challenge status enumeration.
     */
    public enum Status {
        PENDING, PROCESSING, VALID, INVALID, REVOKED, UNKNOWN;
    }

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    String getType();

    /**
     * Returns the {@link URI} of the challenge.
     */
    URI getUri();

    /**
     * Returns the current status of the challenge.
     */
    Status getStatus();

    /**
     * Returns the validation date, if returned by the server.
     */
    Date getValidated();

    /**
     * Authorizes a {@link Challenge} by signing it with an {@link Account}. This is
     * required before triggering the challenge.
     *
     * @param account
     *            {@link Account} to sign the challenge with
     */
    void authorize(Account account);

    /**
     * Sets the challenge state by reading the given JSON map.
     *
     * @param map
     *            JSON map containing the challenge data
     */
    void unmarshall(Map<String, Object> map);

    /**
     * Copies the current challenge state to the claim builder, as preparation for
     * triggering it.
     *
     * @param cb
     *            {@link ClaimBuilder} to copy the challenge state to
     */
    void marshall(ClaimBuilder cb);

}
