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

import java.net.URL;
import java.time.Instant;
import java.util.Objects;

import org.shredzone.acme4j.AcmeJsonResource;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
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
     * @param session
     *            {@link Session} to bind to.
     * @param data
     *            {@link JSON} challenge data
     */
    public Challenge(Session session, JSON data) {
        super(session, data);
    }

    /**
     * Returns a {@link Challenge} object of an existing challenge.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Challenge location
     * @return {@link Challenge} bound to this session and location
     */
    @SuppressWarnings("unchecked")
    public static <T extends Challenge> T bind(Session session, URL location) throws AcmeException {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(location, "location");

        LOG.debug("bind");
        try (Connection conn = session.provider().connect()) {
            conn.sendRequest(location, session);

            JSON json = conn.readJsonResponse();
            if (!(json.contains(KEY_TYPE))) {
                throw new IllegalArgumentException("Provided URL is not a challenge URL");
            }

            return (T) session.createChallenge(json);
        }
    }

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    public String getType() {
        return getJSON().get(KEY_TYPE).asString();
    }

    /**
     * Returns the current status of the challenge.
     */
    public Status getStatus() {
        return getJSON().get(KEY_STATUS).asStatusOrElse(Status.UNKNOWN);
    }

    /**
     * Returns the validation date, if returned by the server.
     */
    public Instant getValidated() {
        return getJSON().get(KEY_VALIDATED).asInstant();
    }

    /**
     * Returns a reason why the challenge has failed in the past, if returned by the
     * server. If there are multiple errors, they can be found in
     * {@link Problem#getSubProblems()}.
     */
    public Problem getError() {
        return getJSON().get(KEY_ERROR).asProblem(getLocation());
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
        String type = json.get(KEY_TYPE).required().asString();

        if (!acceptable(type)) {
            throw new AcmeProtocolException("incompatible type " + type + " for this challenge");
        }

        setLocation(json.get(KEY_URL).required().asURL());

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
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            prepareResponse(claims);

            conn.sendSignedRequest(getLocation(), claims, getSession());

            setJSON(conn.readJsonResponse());
        }
    }

}
