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
import static org.shredzone.acme4j.toolbox.AcmeUtils.sha256hash;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge. It requires a specific DNS record for domain
 * validation. See the acme4j documentation for a detailed explanation.
 */
public class Dns01Challenge extends TokenChallenge {
    private static final long serialVersionUID = 6964687027713533075L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-01";

    /**
     * The prefix of the domain name to be used for the DNS TXT record.
     */
    public static final String RECORD_NAME_PREFIX = "_acme-challenge";

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param identifier
     *         Domain {@link Identifier} of the domain to be validated
     * @return Resource Record name (e.g. {@code _acme-challenge.www.example.org.}, note
     * the trailing full stop character).
     * @since 2.14
     */
    public static String toRRName(Identifier identifier) {
        return toRRName(identifier.getDomain());
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param domain
     *         Domain name to be validated
     * @return Resource Record name (e.g. {@code _acme-challenge.www.example.org.}, note
     * the trailing full stop character).
     * @since 2.14
     */
    public static String toRRName(String domain) {
        return RECORD_NAME_PREFIX + '.' + domain + '.';
    }

    /**
     * Creates a new generic {@link Dns01Challenge} object.
     *
     * @param login
     *         {@link Login} the resource is bound with
     * @param data
     *         {@link JSON} challenge data
     */
    public Dns01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Returns the digest string to be set in the domain's {@code _acme-challenge} TXT
     * record.
     */
    public String getDigest() {
        return base64UrlEncode(sha256hash(getAuthorization()));
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
