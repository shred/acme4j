/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2024 Richard "Shred" Körber
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

import static java.time.Instant.now;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.shredzone.acme4j.exception.AcmeException;

/**
 * Marks an ACME Resource with a pollable status.
 * <p>
 * The resource provides a status, and a method for updating the internal cache to read
 * the current status from the server.
 *
 * @since 3.4.0
 */
public interface PollableResource {

    /**
     * Default delay between status polls if there is no Retry-After header.
     */
    Duration DEFAULT_RETRY_AFTER = Duration.ofSeconds(3L);

    /**
     * Returns the current status of the resource.
     */
    Status getStatus();

    /**
     * Fetches the current status from the server.
     *
     * @return Retry-After time, if given by the CA, otherwise empty.
     */
    Optional<Instant> fetch() throws AcmeException;

    /**
     * Waits until a terminal status has been reached, by polling until one of the given
     * status or the given timeout has been reached. This call honors the Retry-After
     * header if set by the CA.
     * <p>
     * This method is synchronous and blocks the current thread.
     * <p>
     * If the resource is already in a terminal status, the method returns immediately.
     *
     * @param statusSet
     *         Set of {@link Status} that are accepted as terminal
     * @param timeout
     *         Timeout until a terminal status must have been reached
     * @return Status that was reached
     */
    default Status waitForStatus(Set<Status> statusSet, Duration timeout)
            throws AcmeException, InterruptedException {
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(statusSet, "statusSet");
        if (statusSet.isEmpty()) {
            throw new IllegalArgumentException("At least one Status is required");
        }

        var currentStatus = getStatus();
        if (statusSet.contains(currentStatus)) {
            return currentStatus;
        }

        var timebox = now().plus(timeout);
        Instant now;

        while ((now = now()).isBefore(timebox)) {
            // Poll status and get the time of the next poll
            var retryAfter = fetch()
                    .orElse(now.plus(DEFAULT_RETRY_AFTER));

            currentStatus = getStatus();
            if (statusSet.contains(currentStatus)) {
                return currentStatus;
            }

            // Preemptively end the loop if the next iteration would be after timebox
            if (retryAfter.isAfter(timebox)) {
                break;
            }

            // Wait until retryAfter is reached
            Thread.sleep(now.until(retryAfter, ChronoUnit.MILLIS));
        }

        throw new AcmeException("Timeout has been reached");
    }

}
