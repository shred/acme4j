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

import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import org.shredzone.acme4j.Session;

/**
 * Implements the {@value TYPE} challenge.
 */
public class Dns01Challenge extends TokenChallenge {
    private static final long serialVersionUID = 6964687027713533075L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-01";

    /**
     * Creates a new generic {@link Dns01Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public Dns01Challenge(Session session) {
        super(session);
    }

    /**
     * Returns the digest string to be set in the domain's {@code _acme-challenge} TXT
     * record.
     */
    public String getDigest() {
        return base64UrlEncode(sha256hash(getAuthorization()));
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
