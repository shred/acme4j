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

import java.time.Instant;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.AcmeJsonResource;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A generic challenge. It can be used as a base class for actual challenge
 * implementations, but it is also used if the ACME server offers a proprietary challenge
 * that is unknown to acme4j.
 * <p>
 * Subclasses must override {@link Challenge#acceptable(String)} so it only accepts the
 * own type. {@link Challenge#prepareResponse(JSONBuilder)} should be overridden to put
 * all required data to the response.
 */
@ParametersAreNonnullByDefault
public class Challenge extends AcmeJsonResource {
    private static final long serialVersionUID = 2338794776848388099L;
    private static final Logger LOG = LoggerFactory.getLogger(Challenge.class);

    protected static final String KEY_TYPE = "type";
    protected static final String KEY_URL = "url";
    protected static final String KEY_STATUS = "status";
    protected static final String KEY_VALIDATED = "validated";
    protected static final String KEY_ERROR = "error";

    /**
     * Creates a new generic {@link Challenge} object.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param data
     *            {@link JSON} challenge data
     */
    public Challenge(Login login, JSON data) {
        super(login, data.get(KEY_URL).asURL());
        setJSON(data);
    }

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    public String getType() {
        return getJSON().get(KEY_TYPE).asString();
    }

    /**
     * Returns the current status of the challenge.
     * <p>
     * Possible values are: {@link Status#PENDING}, {@link Status#PROCESSING},
     * {@link Status#VALID}, {@link Status#INVALID}.
     */
    public Status getStatus() {
        return getJSON().get(KEY_STATUS).asStatus();
    }

    /**
     * Returns the validation date, if returned by the server.
     */
    @CheckForNull
    public Instant getValidated() {
        return getJSON().get(KEY_VALIDATED).map(Value::asInstant).orElse(null);
    }

    /**
     * Returns a reason why the challenge has failed in the past, if returned by the
     * server. If there are multiple errors, they can be found in
     * {@link Problem#getSubProblems()}.
     */
    @CheckForNull
    public Problem getError() {
        return getJSON().get(KEY_ERROR)
                    .map(it -> it.asProblem(getLocation()))
                    .orElse(null);
    }

    /**
     * Exports the response state, as preparation for triggering the challenge.
     *
     * @param response
     *            {@link JSONBuilder} to write the response to
     */
    protected void prepareResponse(JSONBuilder response) {
        // Do nothing here...
    }

    /**
     * Checks if the type is acceptable to this challenge.
     *
     * @param type
     *            Type to check
     * @return {@code true} if acceptable, {@code false} if not
     */
    protected boolean acceptable(String type) {
        return type != null && !type.trim().isEmpty();
    }

    @Override
    protected void setJSON(JSON json) {
        String type = json.get(KEY_TYPE).asString();

        if (!acceptable(type)) {
            throw new AcmeProtocolException("incompatible type " + type + " for this challenge");
        }

        String loc = json.get(KEY_URL).asString();
        if (loc != null && !loc.equals(getLocation().toString())) {
            throw new AcmeProtocolException("challenge has changed its location");
        }

        super.setJSON(json);
    }

    /**
     * Triggers this {@link Challenge}. The ACME server is requested to validate the
     * response. Note that the validation is performed asynchronously by the ACME server.
     * <p>
     * If this method is invoked a second time, the ACME server is requested to retry the
     * validation. This can be useful if the client state has changed, for example after a
     * firewall rule has been updated.
     */
    public void trigger() throws AcmeException {
        LOG.debug("trigger");
        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
            prepareResponse(claims);

            conn.sendSignedRequest(getLocation(), claims, getLogin());

            JSON json = conn.readJsonResponse();
            if (json != null) {
                setJSON(json);
            }
        }
    }

}
