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

    /**
     * The server has created the resource, and is waiting for the client to process it.
     */
    PENDING,

    /**
     * The {@link Order} is ready to be finalized. Invoke {@link Order#execute(byte[])}.
     */
    READY,

    /**
     * The server is processing the resource. The client should invoke
     * {@link AcmeJsonResource#update()} and re-check the status.
     */
    PROCESSING,

    /**
     * The resource is valid and can be used as intended.
     */
    VALID,

    /**
     * An error or authorization/validation failure has occured. The client should check
     * for error messages.
     */
    INVALID,

    /**
     * The {@link Authorization} has been revoked by the server.
     */
    REVOKED,

    /**
     * The {@link Account} or {@link Authorization} has been deactivated by the client.
     */
    DEACTIVATED,

    /**
     * The {@link Authorization} is expired.
     */
    EXPIRED,

    /**
     * An auto-renewing {@link Order} is canceled.
     *
     * @since 2.3
     */
    CANCELED,

    /**
     * The server did not provide a status, or the provided status is not a specified ACME
     * status.
     */
    UNKNOWN;

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

}
