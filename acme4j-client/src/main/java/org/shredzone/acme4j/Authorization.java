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

import static java.util.stream.Collectors.toList;
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an authorization request at the ACME server.
 */
public class Authorization extends AcmeResource {
    private static final long serialVersionUID = -3116928998379417741L;
    private static final Logger LOG = LoggerFactory.getLogger(Authorization.class);

    private String domain;
    private Status status;
    private Instant expires;
    private List<Challenge> challenges;
    private boolean loaded = false;

    protected Authorization(Session session, URL location) {
        super(session);
        setLocation(location);
    }

    /**
     * Creates a new instance of {@link Authorization} and binds it to the
     * {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location of the Authorization
     * @return {@link Authorization} bound to the session and location
     */
    public static Authorization bind(Session session, URL location) {
        return new Authorization(session, location);
    }

    /**
     * Gets the domain name to be authorized.
     */
    public String getDomain() {
        load();
        return domain;
    }

    /**
     * Gets the authorization status.
     */
    public Status getStatus() {
        load();
        return status;
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Instant getExpires() {
        load();
        return expires;
    }

    /**
     * Gets a list of all challenges offered by the server.
     */
    public List<Challenge> getChallenges() {
        load();
        return challenges;
    }

    /**
     * Finds a {@link Challenge} of the given type. Responding to this {@link Challenge}
     * is sufficient for authorization.
     *
     * @param type
     *            Challenge name (e.g. "http-01")
     * @return {@link Challenge} matching that name, or {@code null} if there is no such
     *         challenge, or if the challenge alone is not sufficient for authorization.
     * @throws ClassCastException
     *             if the type does not match the expected Challenge class type
     */
    @SuppressWarnings("unchecked")
    public <T extends Challenge> T findChallenge(final String type) {
        return (T) getChallenges().stream()
                .filter(ch -> type.equals(ch.getType()))
                .reduce((a, b) -> {throw new AcmeProtocolException("Found more than one challenge of type " + type);})
                .orElse(null);
    }

    /**
     * Updates the {@link Authorization}. After invocation, the {@link Authorization}
     * reflects the current state at the ACME server.
     *
     * @throws AcmeRetryAfterException
     *             the auhtorization is still being validated, and the server returned an
     *             estimated date when the validation will be completed. If you are
     *             polling for the authorization to complete, you should wait for the date
     *             given in {@link AcmeRetryAfterException#getRetryAfter()}. Note that the
     *             authorization status is updated even if this exception was thrown.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            conn.sendRequest(getLocation(), getSession());

            unmarshalAuthorization(conn.readJsonResponse());

            conn.handleRetryAfter("authorization is not completed yet");
        }
    }

    /**
     * Permanently deactivates the {@link Authorization}.
     */
    public void deactivate() throws AcmeException {
        LOG.debug("deactivate");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.put("status", "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getSession());

            unmarshalAuthorization(conn.readJsonResponse());
        }
    }

    /**
     * Lazily updates the object's state when one of the getters is invoked.
     */
    protected void load() {
        if (!loaded) {
            try {
                update();
            } catch (AcmeRetryAfterException ex) {
                // ignore... The object was still updated.
                LOG.debug("Retry-After", ex);
            } catch (AcmeException ex) {
                throw new AcmeLazyLoadingException(this, ex);
            }
        }
    }

    /**
     * Sets the properties according to the given JSON data.
     *
     * @param json
     *            JSON data
     */
    protected void unmarshalAuthorization(JSON json) {
        this.status = json.get("status").asStatusOrElse(Status.PENDING);

        String jsonExpires = json.get("expires").asString();
        if (jsonExpires != null) {
            expires = parseTimestamp(jsonExpires);
        }

        JSON jsonIdentifier = json.get("identifier").asObject();
        if (jsonIdentifier != null) {
            String type = jsonIdentifier.get("type").asString();
            if (type != null && !"dns".equals(type)) {
                throw new AcmeProtocolException("Unknown authorization type: " + type);
            }
            domain = jsonIdentifier.get("value").asString();
        }

        challenges = fetchChallenges(json);

        loaded = true;
    }

    /**
     * Fetches all {@link Challenge} that are defined in the JSON.
     *
     * @param json
     *            {@link JSON} to read
     * @return List of {@link Challenge}
     */
    private List<Challenge> fetchChallenges(JSON json) {
        Session session = getSession();

        return Collections.unmodifiableList(json.get("challenges").asArray().stream()
                .map(JSON.Value::asObject)
                .map(session::createChallenge)
                .collect(toList()));
    }

}
