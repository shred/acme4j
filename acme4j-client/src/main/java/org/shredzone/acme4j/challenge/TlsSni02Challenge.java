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

import static org.shredzone.acme4j.util.AcmeUtils.*;

import org.shredzone.acme4j.Session;

/**
 * Implements the {@value TYPE} challenge.
 */
public class TlsSni02Challenge extends TokenChallenge {
    private static final long serialVersionUID = 8921833167878544518L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-sni-02";

    private String subject;
    private String sanB;

    /**
     * Creates a new generic {@link TlsSni02Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public TlsSni02Challenge(Session session) {
        super(session);
    }

    /**
     * Returns the subject, which is to be used as "SAN-A" in a self-signed certificate.
     * The CA will send the SNI request against this domain.
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Returns the key authorization, which is to be used as "SAN-B" in a self-signed
     * certificate.
     */
    public String getSanB() {
        return sanB;
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

    @Override
    protected void authorize() {
        super.authorize();

        String tokenHash = hexEncode(sha256hash(getToken()));
        subject = tokenHash.substring(0, 32) + '.' + tokenHash.substring(32) + ".token.acme.invalid";

        String kaHash = hexEncode(sha256hash(getAuthorization()));
        sanB = kaHash.substring(0, 32) + '.' + kaHash.substring(32) + ".ka.acme.invalid";
    }

}
