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
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Implements the {@value TYPE} challenge.
 *
 * @author Richard "Shred" Körber
 */
public class Dns01Challenge extends GenericTokenChallenge {
    private static final long serialVersionUID = 6964687027713533075L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-01";

    /**
     * Returns the digest string to be set in the domain's {@code _acme-challenge} TXT
     * record.
     */
    public String getDigest() {
        assertIsAuthorized();

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(getAuthorization().getBytes("UTF-8"));
            byte[] digest = md.digest();
            return Base64Url.encode(digest);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new AcmeProtocolException("Failed to compute digest", ex);
        }
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
