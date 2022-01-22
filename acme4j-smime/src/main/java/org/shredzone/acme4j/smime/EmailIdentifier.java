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
package org.shredzone.acme4j.smime;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Represents an e-mail identifier.
 *
 * @since 2.12
 */
public class EmailIdentifier extends Identifier {
    private static final long serialVersionUID = -1473014167038845395L;

    /**
     * Type constant for E-Mail identifiers.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
     */
    public static final String TYPE_EMAIL = "email";

    /**
     * Creates a new {@link EmailIdentifier}.
     *
     * @param value
     *         e-mail address
     */
    private EmailIdentifier(String value) {
        super(TYPE_EMAIL, value);
    }

    /**
     * Creates a new email identifier for the given address.
     *
     * @param email
     *         Email address. Must only be the address itself (without personal name).
     * @return New {@link EmailIdentifier}
     */
    public static EmailIdentifier email(String email) {
        return new EmailIdentifier(email);
    }

    /**
     * Creates a new email identifier for the given address.
     *
     * @param email
     *         Email address. Only the address itself is used. The personal name will be
     *         ignored.
     * @return New {@link EmailIdentifier}
     */
    public static EmailIdentifier email(InternetAddress email) {
        return email(email.getAddress());
    }

    /**
     * Returns the email address.
     *
     * @return {@link InternetAddress}
     * @throws AcmeProtocolException
     *             if this is not a valid email identifier.
     */
    public InternetAddress getEmailAddress() {
        try {
            return new InternetAddress(getValue());
        } catch (AddressException ex) {
            throw new AcmeProtocolException("bad email address", ex);
        }
    }

}
