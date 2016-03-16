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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Implements the {@value TYPE} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class TlsSni01Challenge extends GenericTokenChallenge {
    private static final long serialVersionUID = 7370329525205430573L;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-sni-01";

    private String subject;

    /**
     * Return the subject to generate a self-signed certificate for.
     */
    public String getSubject() {
        assertIsAuthorized();
        return subject;
    }

    @Override
    public void authorize(Registration registration) {
        super.authorize(registration);
        String hash = computeHash(getAuthorization());
        subject = hash.substring(0, 32) + '.' + hash.substring(32) + ".acme.invalid";
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
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
