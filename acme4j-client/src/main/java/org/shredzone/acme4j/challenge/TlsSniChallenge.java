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

import org.jose4j.base64url.Base64Url;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Implements the {@code tls-sni-01} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class TlsSniChallenge extends GenericChallenge {
    private static final long serialVersionUID = 7370329525205430573L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-sni-01";

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private String authorization = null;
    private String subject = null;

    /**
     * Returns the token to be used for this challenge.
     */
    public String getToken() {
        return get(KEY_TOKEN);
    }

    /**
     * Sets the token to be used.
     */
    public void setToken(String token) {
        put(KEY_TOKEN, token);
    }

    /**
     * Returns the authorization string.
     */
    public String getAuthorization() {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }
        return authorization;
    }

    /**
     * Return the subject to generate a self-signed certificate for.
     */
    public String getSubject() {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }
        return subject;
    }

    /**
     * Authorizes the {@link Challenge} by signing it with an {@link Account}.
     *
     * @param account
     *            {@link Account} to sign the challenge with
     */
    public void authorize(Account account) {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }

        authorization = getToken() + '.' + Base64Url.encode(jwkThumbprint(account.getKeyPair().getPublic()));

        String hash = computeHash(authorization);
        subject = hash.substring(0, 32) + '.' + hash.substring(32) + ".acme.invalid";
    }

    @Override
    public void marshall(ClaimBuilder cb) {
        cb.put(KEY_KEY_AUTHORIZSATION, getAuthorization());
        cb.put(KEY_TYPE, getType());
        cb.put(KEY_TOKEN, getToken());
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
            // Algorithm and Encoding are standard on Java
            throw new RuntimeException(ex);
        }
    }

}
