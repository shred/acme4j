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
 *
 * @deprecated This challenge is vulnerable and will be removed from the ACME specs. Do
 *             not use! Let's Encrypt does not offer this challenge to the general public
 *             any more.
 */
@Deprecated
public class TlsSni01Challenge extends TokenChallenge {
    private static final long serialVersionUID = 7370329525205430573L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-sni-01";

    private String subject;

    /**
     * Creates a new generic {@link TlsSni01Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public TlsSni01Challenge(Session session) {
        super(session);
    }

    /**
     * Return the subject to generate a self-signed certificate for.
     */
    public String getSubject() {
        return subject;
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

    @Override
    protected void authorize() {
        super.authorize();

        String hash = hexEncode(sha256hash(getAuthorization()));
        subject = hash.substring(0, 32) + '.' + hash.substring(32) + ".acme.invalid";
    }

}
