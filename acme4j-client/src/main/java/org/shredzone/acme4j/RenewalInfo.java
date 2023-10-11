/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
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

import java.net.URL;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renewal Information of a certificate.
 *
 * @draft This class is currently based on an RFC draft. It may be changed or
 * removed without notice to reflect future changes to the draft. SemVer rules
 * do not apply here.
 * @since 3.0.0
 */
public class RenewalInfo extends AcmeJsonResource {
    private static final Logger LOG = LoggerFactory.getLogger(RenewalInfo.class);

    private @Nullable Instant recheckAfter = null;

    protected RenewalInfo(Login login, URL location) {
        super(login, location);
    }

    /**
     * Returns the starting {@link Instant} of the time window the CA recommends for
     * certificate renewal.
     */
    public Instant getSuggestedWindowStart() {
        return getJSON().get("suggestedWindow").asObject().get("start").asInstant();
    }

    /**
     * Returns the ending {@link Instant} of the time window the CA recommends for
     * certificate renewal.
     */
    public Instant getSuggestedWindowEnd() {
        return getJSON().get("suggestedWindow").asObject().get("end").asInstant();
    }

    /**
     * An optional {@link URL} pointing to a page which may explain why the suggested
     * renewal window is what it is.
     */
    public Optional<URL> getExplanation() {
        return getJSON().get("explanationURL").optional().map(Value::asURL);
    }

    /**
     * An optional {@link Instant} that serves as recommendation when to re-check the
     * renewal information of a certificate.
     */
    public Optional<Instant> getRecheckAfter() {
        getJSON();  // make sure resource is loaded
        return Optional.ofNullable(recheckAfter);
    }

    /**
     * Checks if the given {@link Instant} is before the suggested time window, so a
     * certificate renewal is not required yet.
     *
     * @param instant
     *         {@link Instant} to check
     * @return {@code true} if the {@link Instant} is before the time window, {@code
     * false} otherwise.
     */
    public boolean renewalIsNotRequired(Instant instant) {
        assertValidTimeWindow();
        return instant.isBefore(getSuggestedWindowStart());
    }

    /**
     * Checks if the given {@link Instant} is within the suggested time window, and a
     * certificate renewal is recommended.
     * <p>
     * An {@link Instant} is deemed to be within the time window if it is equal to, or
     * after {@link #getSuggestedWindowStart()}, and before {@link
     * #getSuggestedWindowEnd()}.
     *
     * @param instant
     *         {@link Instant} to check
     * @return {@code true} if the {@link Instant} is within the time window, {@code
     * false} otherwise.
     */
    public boolean renewalIsRecommended(Instant instant) {
        assertValidTimeWindow();
        return !instant.isBefore(getSuggestedWindowStart())
                && instant.isBefore(getSuggestedWindowEnd());
    }

    /**
     * Checks if the given {@link Instant} is past the time window, and a certificate
     * renewal is overdue.
     * <p>
     * An {@link Instant} is deemed to be past the time window if it is equal to, or after
     * {@link #getSuggestedWindowEnd()}.
     *
     * @param instant
     *         {@link Instant} to check
     * @return {@code true} if the {@link Instant} is past the time window, {@code false}
     * otherwise.
     */
    public boolean renewalIsOverdue(Instant instant) {
        assertValidTimeWindow();
        return !instant.isBefore(getSuggestedWindowEnd());
    }

    /**
     * Returns a proposed {@link Instant} when the certificate related to this
     * {@link RenewalInfo} should be renewed.
     * <p>
     * This method is useful for setting alarms for renewal cron jobs. As a parameter, the
     * frequency of the cron job is set. The resulting {@link Instant} is guaranteed to be
     * executed in time, considering the cron job intervals.
     * <p>
     * This method uses {@link ThreadLocalRandom} for random numbers. It is sufficient for
     * most cases, as only an "earliest" {@link Instant} is returned, but the actual
     * renewal process also depends on cron job execution times and other factors like
     * system load.
     * <p>
     * The result is empty if it is impossible to renew the certificate in time, under the
     * given circumstances. This is either because the time window already ended in the
     * past, or because the cron job would not be executed before the ending of the time
     * window. In this case, it is recommended to renew the certificate immediately.
     *
     * @param frequency
     *         Frequency of the cron job executing the certificate renewals. May be
     *         {@code null} if there is no cron job, and the renewal is going to be
     *         executed exactly at the given {@link Instant}.
     * @return Random {@link Instant} when the certificate should be renewed. This instant
     * might be slightly in the past. In this case, start the renewal process at the next
     * possible regular moment.
     */
    public Optional<Instant> getRandomProposal(@Nullable TemporalAmount frequency) {
        assertValidTimeWindow();
        Instant start = Instant.now();
        Instant suggestedStart = getSuggestedWindowStart();
        if (start.isBefore(suggestedStart)) {
            start = suggestedStart;
        }

        Instant end = getSuggestedWindowEnd();
        if (frequency != null) {
            end = end.minus(frequency);
        }

        if (!end.isAfter(start)) {
            return Optional.empty();
        }

        return Optional.of(Instant.ofEpochMilli(ThreadLocalRandom.current().nextLong(
                start.toEpochMilli(),
                end.toEpochMilli())));
    }

    @Override
    public void update() throws AcmeException {
        LOG.debug("update RenewalInfo");
        try (Connection conn = getSession().connect()) {
            conn.sendRequest(getLocation(), getSession(), null);
            setJSON(conn.readJsonResponse());
            recheckAfter = conn.getRetryAfter().orElse(null);
        }
    }

    /**
     * Asserts that the end of the suggested time window is after the start.
     */
    private void assertValidTimeWindow() {
        if (getSuggestedWindowStart().isAfter(getSuggestedWindowEnd())) {
            throw new AcmeProtocolException("Received an invalid suggested window");
        }
    }

}
