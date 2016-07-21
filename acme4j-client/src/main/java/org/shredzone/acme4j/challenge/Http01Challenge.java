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

import java.net.InetAddress;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Implements the {@value TYPE} challenge.
 */
public class Http01Challenge extends TokenChallenge {
    private static final long serialVersionUID = 3322211185872544605L;

    protected static final String KEY_ADDRESS = "address";

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "http-01";

    private InetAddress address;

    /**
     * Creates a new generic {@link Http01Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public Http01Challenge(Session session) {
        super(session);
    }

    /**
     * Returns the token to be used for this challenge.
     */
    @Override
    public String getToken() {
        return super.getToken();
    }

    /**
     * Returns the authorization string to be used for the response.
     * <p>
     * <em>NOTE:</em> The response file must only contain the returned String (UTF-8
     * or ASCII encoded). There must not be any other leading or trailing characters
     * (like white-spaces or line breaks). Otherwise the challenge will fail.
     */
    @Override
    public String getAuthorization() {
        return super.getAuthorization();
    }

    /**
     * An address that the CA server should connect to in order to request the response.
     * This address must be included in the set of IP addresses to which the domain name
     * resolves.
     * <p>
     * It is at the discretion of the CA server to use this address for the request.
     * However, if the address is not included in the set of IP addresses, the challenge
     * will fail.
     *
     * @param address
     *            Address to request the response from
     */
    public void setAddress(InetAddress address) {
        this.address = address;
    }

    @Override
    protected void respond(ClaimBuilder cb) {
        super.respond(cb);
        if (address != null) {
            cb.put(KEY_ADDRESS, address.getHostAddress());
        }
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
