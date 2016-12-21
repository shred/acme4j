/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import java.net.URL;

import org.shredzone.acme4j.Session;

/**
 * Implements the {@value TYPE} challenge.
 */
public class OutOfBand01Challenge extends Challenge {
    private static final long serialVersionUID = -7459595198486630582L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "oob-01";

    /**
     * Creates a new generic {@link OutOfBand01Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public OutOfBand01Challenge(Session session) {
        super(session);
    }

    /**
     * Returns the validation URL to be visited by the customer in order to complete the
     * challenge.
     */
    public URL getValidationUrl() {
        return getJSON().get("href").asURL();
    }

}
