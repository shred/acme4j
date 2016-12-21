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

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A generic challenge. It can be used as a base class for actual challenge
 * implementations, but it is also used if the ACME server offers a proprietary challenge
 * that is unknown to acme4j.
 * <p>
 * Subclasses must override {@link Challenge#acceptable(String)} so it only accepts the
 * own type. {@link Challenge#respond(JSONBuilder)} should be overridden to put all
 * required data to the response.
 */
public class Challenge extends AcmeResource {
    private static final long serialVersionUID = 2338794776848388099L;
    private static final Logger LOG = LoggerFactory.getLogger(Challenge.class);

    protected static final String KEY_TYPE = "type";
    protected static final String KEY_STATUS = "status";
    protected static final String KEY_URI = "uri";
    protected static final String KEY_VALIDATED = "validated";

    private JSON data = JSON.empty();

    /**
     * Creates a new generic {@link Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public Challenge(Session session) {
        super(session);
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
    public static <T extends Challenge> T bind(Session session, URI location) throws AcmeException {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(location, "location");

        LOG.debug("bind");
        try (Connection conn = session.provider().connect()) {
            conn.sendRequest(location, session);
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);

            JSON json = conn.readJsonResponse();
            if (!(json.contains("type"))) {
                throw new IllegalArgumentException("Provided URI is not a challenge URI");
            }

            return (T) session.createChallenge(json);
        }
    }

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    public String getType() {
        return data.get(KEY_TYPE).asString();
    }

    /**
     * Returns the current status of the challenge.
     */
    public Status getStatus() {
        return Status.parse(data.get(KEY_STATUS).asString(), Status.PENDING);
    }

    /**
     * Returns the location {@link URI} of the challenge.
     */
    @Override
    public URI getLocation() {
        return data.get(KEY_URI).asURI();
    }

    /**
     * Returns the validation date, if returned by the server.
     */
    public Date getValidated() {
        return data.get(KEY_VALIDATED).asDate();
    }

    /**
     * Returns the JSON representation of the challenge data.
     */
    protected JSON getJSON() {
        return data;
    }

    /**
     * Exports the response state, as preparation for triggering the challenge.
     *
     * @param cb
     *            {@link JSONBuilder} to copy the response to
     */
    protected void respond(JSONBuilder cb) {
        cb.put(KEY_TYPE, getType());
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

    /**
     * Sets the challenge state to the given JSON map.
     *
     * @param json
     *            JSON containing the challenge data
     */
    public void unmarshall(JSON json) {
        String type = json.get(KEY_TYPE).asString();
        if (type == null) {
            throw new IllegalArgumentException("map does not contain a type");
        }
        if (!acceptable(type)) {
            throw new AcmeProtocolException("wrong type: " + type);
        }

        data = json;
        authorize();
    }

    /**
     * Callback that is invoked when the challenge is supposed to compute its
     * authorization data.
     */
    protected void authorize() {
        // Does nothing here...
    }

    /**
     * Triggers this {@link Challenge}. The ACME server is requested to validate the
     * response. Note that the validation is performed asynchronously by the ACME server.
     */
    public void trigger() throws AcmeException {
        LOG.debug("trigger");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource("challenge");
            respond(claims);

            conn.sendSignedRequest(getLocation(), claims, getSession());
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);

            unmarshall(conn.readJsonResponse());
        }
    }

    /**
     * Updates the state of this challenge.
     *
     * @throws AcmeRetryAfterException
     *             the challenge is still being validated, and the server returned an
     *             estimated date when the challenge will be completed. If you are polling
     *             for the challenge to complete, you should wait for the date given in
     *             {@link AcmeRetryAfterException#getRetryAfter()}. Note that the
     *             challenge status is updated even if this exception was thrown.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            conn.sendRequest(getLocation(), getSession());
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);

            unmarshall(conn.readJsonResponse());

            conn.handleRetryAfter("challenge is not completed yet");
        }
    }

}
