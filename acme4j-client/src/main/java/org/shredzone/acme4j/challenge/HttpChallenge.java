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

import org.jose4j.base64url.Base64Url;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Implements the {@code http-01} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class HttpChallenge extends GenericChallenge {
    private static final long serialVersionUID = 3322211185872544605L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "http-01";

    private String authorization = null;

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
     * Returns the authorization string to be used for the response.
     * <p>
     * <em>NOTE:</em> The response file must only contain the returned String (UTF-8
     * or ASCII encoded). There must not be any other leading or trailing characters
     * (like white-spaces or line breaks). Otherwise the challenge will fail.
     */
    public String getAuthorization() {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }
        return authorization;
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

}
