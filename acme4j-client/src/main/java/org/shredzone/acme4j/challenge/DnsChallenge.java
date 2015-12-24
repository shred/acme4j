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
 * Implements the {@code dns-01} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class DnsChallenge extends GenericChallenge {
    private static final long serialVersionUID = 6964687027713533075L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-01";

    private String authorization = null;

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
    }

    /**
     * Returns the digest string to be set in the domain's {@code _acme-challenge} TXT
     * record.
     */
    public String getDigest() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(getAuthorization().getBytes("UTF-8"));
            byte[] digest = md.digest();
            return Base64Url.encode(digest);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            // both should be standard in JDK...
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void respond(ClaimBuilder cb) {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }

        super.respond(cb);
        cb.put(KEY_TOKEN, getToken());
        cb.put(KEY_KEY_AUTHORIZATION, getAuthorization());
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

    private String getToken() {
        return get(KEY_TOKEN);
    }

    private String getAuthorization() {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }

        return authorization;
    }

}
