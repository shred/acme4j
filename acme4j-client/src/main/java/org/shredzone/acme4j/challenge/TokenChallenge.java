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

import static org.shredzone.acme4j.toolbox.AcmeUtils.base64UrlEncode;

import java.security.PublicKey;

import javax.annotation.ParametersAreNonnullByDefault;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * An extension of {@link Challenge} that handles challenges with a {@code token} and
 * {@code keyAuthorization}.
 */
@ParametersAreNonnullByDefault
public class TokenChallenge extends Challenge {
    private static final long serialVersionUID = 1634133407432681800L;

    protected static final String KEY_TOKEN = "token";

    /**
     * Creates a new generic {@link TokenChallenge} object.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param data
     *            {@link JSON} challenge data
     */
    public TokenChallenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Gets the token.
     */
    protected String getToken() {
        String token = getJSON().get(KEY_TOKEN).asString();
        if (!AcmeUtils.isValidBase64Url(token)) {
            throw new AcmeProtocolException("Invalid token: " + token);
        }
        return token;
    }

    /**
     * Returns the authorization string.
     * <p>
     * The default is {@code token + '.' + base64url(jwkThumbprint)}. Subclasses may
     * override this method if a different algorithm is used.
     */
    public String getAuthorization() {
        try {
            PublicKey pk = getLogin().getKeyPair().getPublic();
            PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(pk);
            return getToken()
                        + '.'
                        + base64UrlEncode(jwk.calculateThumbprint("SHA-256"));
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Cannot compute key thumbprint", ex);
        }
    }

}
