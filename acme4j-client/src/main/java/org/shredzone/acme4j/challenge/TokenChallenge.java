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

import java.security.PublicKey;

import org.jose4j.base64url.Base64Url;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.SignatureUtils;

/**
 * An extension of {@link Challenge} that handles challenges with a {@code token} and
 * {@code keyAuthorization}.
 *
 * @author Richard "Shred" Körber
 */
public class TokenChallenge extends Challenge {
    private static final long serialVersionUID = 1634133407432681800L;

    protected static final String KEY_TOKEN = "token";
    protected static final String KEY_KEY_AUTHORIZATION = "keyAuthorization";

    private String authorization;

    /**
     * Creates a new generic {@link TokenChallenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public TokenChallenge(Session session) {
        super(session);
    }

    @Override
    protected void respond(ClaimBuilder cb) {
        super.respond(cb);
        cb.put(KEY_TOKEN, getToken());
        cb.put(KEY_KEY_AUTHORIZATION, getAuthorization());
    }

    /**
     * Gets the token.
     */
    protected String getToken() {
        String token = get(KEY_TOKEN);
        if (token == null) {
            throw new AcmeProtocolException("Challenge token required, but not set");
        }
        return token;
    }

    /**
     * Gets the authorization.
     */
    protected String getAuthorization() {
        return authorization;
    }

    /**
     * Computes the authorization string.
     * <p>
     * The default is {@code token + '.' + base64url(jwkThumbprint)}. Subclasses may
     * override this method if a different algorithm is used.
     *
     * @return Authorization string
     */
    protected String computeAuthorization() {
        PublicKey pk = getSession().getKeyPair().getPublic();
        return getToken()
            + '.'
            + Base64Url.encode(SignatureUtils.jwkThumbprint(pk));
    }

    @Override
    protected void authorize() {
        super.authorize();
        authorization = computeAuthorization();
    }

}
