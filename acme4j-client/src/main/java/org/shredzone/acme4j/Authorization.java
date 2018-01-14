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

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an authorization request at the ACME server.
 */
public class Authorization extends AcmeJsonResource {
    private static final long serialVersionUID = -3116928998379417741L;
    private static final Logger LOG = LoggerFactory.getLogger(Authorization.class);

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
        JSON jsonIdentifier = getJSON().get("identifier").required().asObject();
        String type = jsonIdentifier.get("type").required().asString();
        if (!"dns".equals(type)) {
            throw new AcmeProtocolException("Unknown authorization type: " + type);
        }
        return jsonIdentifier.get("value").required().asString();
    }

    /**
     * Gets the authorization status.
     */
    public Status getStatus() {
        return getJSON().get("status").asStatusOrElse(Status.PENDING);
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Instant getExpires() {
        return getJSON().get("expires").optional()
                    .map(Value::asString)
                    .map(AcmeUtils::parseTimestamp)
                    .orElse(null);
    }

    /**
     * Gets a list of all challenges offered by the server.
     */
    public List<Challenge> getChallenges() {
        Session session = getSession();

        return Collections.unmodifiableList(getJSON().get("challenges")
                    .asArray()
                    .stream()
                    .map(Value::asObject)
                    .map(session::createChallenge)
                    .collect(toList()));
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
     * Permanently deactivates the {@link Authorization}.
     */
    public void deactivate() throws AcmeException {
        LOG.debug("deactivate");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.put("status", "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getSession());

            setJSON(conn.readJsonResponse());
        }
    }

}
