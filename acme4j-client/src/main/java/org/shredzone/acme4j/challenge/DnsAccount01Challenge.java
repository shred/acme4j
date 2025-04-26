/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2025 Richard "Shred" Körber
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

import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import java.io.Serial;
import java.net.URL;
import java.util.Arrays;
import java.util.Locale;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge. It requires a specific DNS record for domain
 * validation. See the acme4j documentation for a detailed explanation.
 *
 * @draft This class is currently based on an RFC draft. It may be changed or removed
 * without notice to reflect future changes to the draft. SemVer rules do not apply here.
 * @since 3.6.0
 */
public class DnsAccount01Challenge extends TokenChallenge {
    @Serial
    private static final long serialVersionUID = -1098129409378900733L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-account-01";

    /**
     * Creates a new generic {@link DnsAccount01Challenge} object.
     *
     * @param login
     *         {@link Login} the resource is bound with
     * @param data
     *         {@link JSON} challenge data
     */
    public DnsAccount01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param identifier
     *         {@link Identifier} to be validated
     * @return Resource Record name (e.g.
     * {@code _ujmmovf2vn55tgye._acme-challenge.example.org.}, note the trailing full stop
     * character).
     */
    public String getRRName(Identifier identifier) {
        return getRRName(identifier.getDomain());
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param domain
     *         Domain name to be validated
     * @return Resource Record name (e.g.
     * {@code _ujmmovf2vn55tgye._acme-challenge.example.org.}, note the trailing full stop
     * character).
     */
    public String getRRName(String domain) {
        return getPrefix(getLogin().getAccount().getLocation()) + '.' + domain + '.';
    }

    /**
     * Returns the digest string to be set in the domain's TXT record.
     */
    public String getDigest() {
        return base64UrlEncode(sha256hash(getAuthorization()));
    }

    /**
     * Returns the prefix of an account location.
     */
    private String getPrefix(URL accountLocation) {
        var urlHash = sha256hash(accountLocation.toExternalForm());
        var hash = base32Encode(Arrays.copyOfRange(urlHash, 0, 10));
        return "_" + hash.toLowerCase(Locale.ENGLISH)
                + "._acme-challenge";
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
