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

import java.io.Serializable;
import java.net.URI;
import java.util.Map;

import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * A challenge.
 *
 * @author Richard "Shred" Körber
 */
public interface Challenge extends Serializable {

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    String getType();

    /**
     * Returns the location {@link URI} of the challenge.
     */
    URI getLocation();

    /**
     * Returns the current status of the challenge.
     */
    Status getStatus();

    /**
     * Returns the validation date, if returned by the server.
     */
    String getValidated();

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
