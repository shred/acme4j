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
import org.shredzone.acme4j.Registration;
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
     * Authorizes the {@link Challenge} by signing it with a {@link Registration}.
     *
     * @param registration
     *            {@link Registration} to sign the challenge with
     */
    public void authorize(Registration registration) {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }

        authorization = computeAuthorization(registration);
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
     *             if {@link #authorize(Registration)} was not invoked.
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
     * Gets the authorization after {@link #authorize(Registration)} was invoked.
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
     * @param registration
     *            {@link Registration} to authorize with
     * @return Authorization string
     */
    protected String computeAuthorization(Registration registration) {
        return getToken()
            + '.'
            + Base64Url.encode(jwkThumbprint(registration.getKeyPair().getPublic()));
    }

}
