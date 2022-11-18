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

import static java.util.stream.Collectors.toUnmodifiableList;

import java.net.URL;
import java.time.Instant;
import java.util.List;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
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

    protected Authorization(Login login, URL location) {
        super(login, location);
    }

    /**
     * Gets the {@link Identifier} to be authorized.
     * <p>
     * For wildcard domain orders, the domain itself (without wildcard prefix) is returned
     * here. To find out if this {@link Authorization} is related to a wildcard domain
     * order, check the {@link #isWildcard()} method.
     *
     * @since 2.3
     */
    public Identifier getIdentifier() {
        return getJSON().get("identifier").asIdentifier();
    }

    /**
     * Gets the authorization status.
     * <p>
     * Possible values are: {@link Status#PENDING}, {@link Status#VALID},
     * {@link Status#INVALID}, {@link Status#DEACTIVATED}, {@link Status#EXPIRED},
     * {@link Status#REVOKED}.
     */
    public Status getStatus() {
        return getJSON().get("status").asStatus();
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    @Nullable
    public Instant getExpires() {
        return getJSON().get("expires")
                    .map(Value::asString)
                    .map(AcmeUtils::parseTimestamp)
                    .orElse(null);
    }

    /**
     * Returns {@code true} if this {@link Authorization} is related to a wildcard domain,
     * {@code false} otherwise.
     */
    public boolean isWildcard() {
        return getJSON().get("wildcard")
                    .map(Value::asBoolean)
                    .orElse(false);
    }

    /**
     * Gets a list of all challenges offered by the server, in no specific order.
     */
    public List<Challenge> getChallenges() {
        var login = getLogin();

        return getJSON().get("challenges")
                .asArray()
                .stream()
                .map(Value::asObject)
                .map(login::createChallenge)
                .collect(toUnmodifiableList());
    }

    /**
     * Finds a {@link Challenge} of the given type. Responding to this {@link Challenge}
     * is sufficient for authorization.
     * <p>
     * {@link Authorization#findChallenge(Class)} should be preferred, as this variant
     * is not type safe.
     *
     * @param type
     *            Challenge name (e.g. "http-01")
     * @return {@link Challenge} matching that name, or {@code null} if there is no such
     *         challenge, or if the challenge alone is not sufficient for authorization.
     * @throws ClassCastException
     *             if the type does not match the expected Challenge class type
     */
    @Nullable
    public <T extends Challenge> T findChallenge(final String type) {
        return (T) getChallenges().stream()
                .filter(ch -> type.equals(ch.getType()))
                .reduce((a, b) -> {throw new AcmeProtocolException("Found more than one challenge of type " + type);})
                .orElse(null);
    }

    /**
     * Finds a {@link Challenge} of the given class type. Responding to this {@link
     * Challenge} is sufficient for authorization.
     *
     * @param type
     *         Challenge type (e.g. "Http01Challenge.class")
     * @return {@link Challenge} of that type, or {@code null} if there is no such
     * challenge, or if the challenge alone is not sufficient for authorization.
     * @since 2.8
     */
    @Nullable
    public <T extends Challenge> T findChallenge(Class<T> type) {
        return getChallenges().stream()
                .filter(type::isInstance)
                .map(type::cast)
                .reduce((a, b) -> {throw new AcmeProtocolException("Found more than one challenge of type " + type.getName());})
                .orElse(null);
    }

    /**
     * Permanently deactivates the {@link Authorization}.
     */
    public void deactivate() throws AcmeException {
        LOG.debug("deactivate");
        try (var conn = getSession().connect()) {
            var claims = new JSONBuilder();
            claims.put("status", "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getLogin());
            setJSON(conn.readJsonResponse());
        }
    }

}
