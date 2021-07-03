/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.challenge;

import static org.shredzone.acme4j.toolbox.AcmeUtils.base64UrlEncode;
import static org.shredzone.acme4j.toolbox.AcmeUtils.sha256hash;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.challenge.TokenChallenge;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
 * @since 2.12
 */
public class EmailReply00Challenge extends TokenChallenge {
    private static final long serialVersionUID = 2502329538019544794L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "email-reply-00";

    private static final String KEY_FROM = "from";

    /**
     * Creates a new generic {@link EmailReply00Challenge} object.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param data
     *            {@link JSON} challenge data
     */
    public EmailReply00Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Returns the email address in the "from" field of the challenge.
     *
     * @return The "from" email address, as String.
     */
    public String getFrom() {
        return getJSON().get(KEY_FROM).asString();
    }

    /**
     * Returns the email address of the expected sender of the "challenge" mail.
     * <p>
     * This is the same value that is returned by {@link #getFrom()}, but as {@link
     * InternetAddress} instance.
     *
     * @return Expected sender of the challenge email.
     */
    public InternetAddress getExpectedSender() {
        try {
            return new InternetAddress(getFrom());
        } catch (AddressException ex) {
            throw new AcmeProtocolException("bad email address " + getFrom(), ex);
        }
    }

    /**
     * Returns the token, which is a concatenation of the part 1 that is sent by email,
     * and part 2 that is passed into this callenge via {@link #getTokenPart2()};
     *
     * @param part1
     *         Part 1 of the token, which can be found in the subject of the corresponding
     *         challenge email.
     * @return Concatenated token
     */
    public String getToken(String part1) {
        return part1.concat(getTokenPart2());
    }

    /**
     * Returns the part 2 of the token to be used for this challenge. Part 2 is sent via
     * this challenge.
     */
    public String getTokenPart2() {
        return super.getToken();
    }

    /**
     * This method is not implemented. Use {@link #getAuthorization(String)} instead.
     */
    @Override
    public String getAuthorization() {
        throw new UnsupportedOperationException("use getAuthorization(String)");
    }

    /**
     * Returns the authorization string.
     *
     * @param part1
     *         Part 1 of the token, which can be found in the subject of the corresponding
     *         challenge email.
     */
    public String getAuthorization(String part1) {
        String keyAuth = keyAuthorizationFor(getToken(part1));
        return base64UrlEncode(sha256hash(keyAuth));
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
