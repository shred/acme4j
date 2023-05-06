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
package org.shredzone.acme4j;

import java.util.Arrays;

/**
 * An enumeration of revocation reasons.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5280#section-5.3.1">RFC 5280 Section
 * 5.3.1</a>
 */
public enum RevocationReason {

    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    REMOVE_FROM_CRL(8),
    PRIVILEGE_WITHDRAWN(9),
    AA_COMPROMISE(10);

    private final int reasonCode;

    RevocationReason(int reasonCode) {
        this.reasonCode = reasonCode;
    }

    /**
     * Returns the reason code as defined in RFC 5280.
     */
    public int getReasonCode() {
        return reasonCode;
    }

    /**
     * Returns the {@link RevocationReason} that matches the reason code.
     *
     * @param reasonCode
     *            Reason code as defined in RFC 5280
     * @return Matching {@link RevocationReason}
     * @throws IllegalArgumentException if the reason code is unknown or invalid
     */
    public static RevocationReason code(int reasonCode) {
        return Arrays.stream(values())
                .filter(rr -> rr.reasonCode == reasonCode)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown revocation reason code: " + reasonCode));
    }

}
