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
package org.shredzone.acme4j;

import java.util.Arrays;

/**
 * Status codes of challenges and authorizations.
 */
public enum Status {

    PENDING, PROCESSING, VALID, INVALID, REVOKED, DEACTIVATED, GOOD, UNKNOWN;

    /**
     * Parses the string and returns a corresponding Status object.
     *
     * @param str
     *            String to parse
     * @return {@link Status} matching the string, or {@link Status#UNKNOWN} if there was
     *         no match
     */
    public static Status parse(String str) {
        String check = str.toUpperCase();
        return Arrays.stream(values())
                .filter(s -> s.name().equals(check))
                .findFirst()
                .orElse(Status.UNKNOWN);
    }

    /**
     * Parses the string and returns a corresponding Status object.
     *
     * @param str
     *            String to parse
     * @param def
     *            Default Status if str is {@code null}
     * @return {@link Status} matching the string, or {@link Status#UNKNOWN} if there was
     *         no match, or {@code def} if the str was {@code null}
     */
    public static Status parse(String str, Status def) {
        return str != null ? parse(str) : def;
    }

}
