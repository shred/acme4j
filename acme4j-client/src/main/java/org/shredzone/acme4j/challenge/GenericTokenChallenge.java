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
 * An extension of {@link GenericChallenge} that handles challenges with a {@code token}
 * and {@code keyAuthorization}.
 *
 * @author Richard "Shred" Körber
 */
public class GenericTokenChallenge extends GenericChallenge {
    private static final long serialVersionUID = 1634133407432681800L;

    protected static final String KEY_TOKEN = "token";
    protected static final String KEY_KEY_AUTHORIZATION = "keyAuthorization";

    private String authorization;

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

        authorization = computeAuthorization(account);
    }

    @Override
    public void respond(ClaimBuilder cb) {
        assertIsAuthorized();

        super.respond(cb);
        cb.put(KEY_TOKEN, getToken());
        cb.put(KEY_KEY_AUTHORIZATION, getAuthorization());
    }

    /**
     * Asserts that the challenge was authorized.
     *
     * @throws IllegalStateException
     *             if {@link #authorize(Account)} was not invoked.
     */
    protected void assertIsAuthorized() {
        if (authorization == null) {
            throw new IllegalStateException("Challenge is not authorized yet");
        }
    }

    /**
     * Gets the token.
     */
    protected String getToken() {
        return get(KEY_TOKEN);
    }

    /**
     * Gets the authorization after {@link #authorize(Account)} was invoked.
     */
    protected String getAuthorization() {
        assertIsAuthorized();
        return authorization;
    }

    /**
     * Computes the authorization string.
     * <p>
     * The default is {@code token + '.' + base64url(jwkThumbprint)}. Subclasses may
     * override this method if a different algorithm is used.
     *
     * @param account
     *            {@link Account} to authorize with
     * @return Authorization string
     */
    protected String computeAuthorization(Account account) {
        return getToken()
            + '.'
            + Base64Url.encode(jwkThumbprint(account.getKeyPair().getPublic()));
    }

}
