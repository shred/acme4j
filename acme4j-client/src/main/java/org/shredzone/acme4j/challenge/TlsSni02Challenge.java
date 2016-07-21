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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Implements the {@value TYPE} challenge.
 */
public class TlsSni02Challenge extends TokenChallenge {
    private static final long serialVersionUID = 8921833167878544518L;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

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

        String tokenHash = computeHash(getToken());
        subject = tokenHash.substring(0, 32) + '.' + tokenHash.substring(32) + ".token.acme.invalid";

        String kaHash = computeHash(getAuthorization());
        sanB = kaHash.substring(0, 32) + '.' + kaHash.substring(32) + ".ka.acme.invalid";
    }

    /**
     * Computes a hash according to the specifications.
     *
     * @param z
     *            Value to be hashed
     * @return Hash
     */
    private String computeHash(String z) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(z.getBytes("UTF-8"));
            byte[] raw = md.digest();
            char[] result = new char[raw.length * 2];
            for (int ix = 0; ix < raw.length; ix++) {
                int val = raw[ix] & 0xFF;
                result[ix * 2] = HEX[val >>> 4];
                result[ix * 2 + 1] = HEX[val & 0x0F];
            }
            return new String(result);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new AcmeProtocolException("Could not compute hash", ex);
        }
    }

}
