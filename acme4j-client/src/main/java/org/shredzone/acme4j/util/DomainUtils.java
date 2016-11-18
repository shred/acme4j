/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.util;

import java.net.IDN;

/**
 * Utility class for domains and domain names.
 */
public final class DomainUtils {

    private DomainUtils() {
        // Utility class without constructor
    }

    /**
     * ASCII encodes a domain name.
     * <p>
     * The conversion is done as described in
     * <a href="http://www.ietf.org/rfc/rfc3490.txt">RFC 3490</a>. Additionally, all
     * leading and trailing white spaces are trimmed, and the result is lowercased.
     * <p>
     * It is safe to pass in ACE encoded domains, they will be returned unchanged.
     *
     * @param domain
     *            Domain name to encode
     * @return Encoded domain name, white space trimmed and lower cased. {@code null} if
     *         {@code null} was passed in.
     */
    public static String toAce(String domain) {
        if (domain == null) {
            return null;
        }
        return IDN.toASCII(domain.trim()).toLowerCase();
    }

}
