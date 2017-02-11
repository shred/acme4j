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

import static org.shredzone.acme4j.util.AcmeUtils.parseTimestamp;

import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
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
    private List<List<Challenge>> combinations;
    private boolean loaded = false;

    protected Authorization(Session session, URI location) {
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
    public static Authorization bind(Session session, URI location) {
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
     * Gets all combinations of challenges supported by the server.
     */
    public List<List<Challenge>> getCombinations() {
        load();
        return combinations;
    }

    /**
     * Finds a single {@link Challenge} of the given type. Responding to this
     * {@link Challenge} is sufficient for authorization. This is a convenience call to
     * {@link #findCombination(String...)}.
     *
     * @param type
     *            Challenge name (e.g. "http-01")
     * @return {@link Challenge} matching that name, or {@code null} if there is no such
     *         challenge, or if the challenge alone is not sufficient for authorization.
     * @throws ClassCastException
     *             if the type does not match the expected Challenge class type
     */
    @SuppressWarnings("unchecked")
    public <T extends Challenge> T findChallenge(String type) {
        Collection<Challenge> result = findCombination(type);
        return !result.isEmpty() ? (T) result.iterator().next() : null;
    }

    /**
     * Finds a combination of {@link Challenge} types that the client supports. The client
     * has to respond to <em>all</em> of the {@link Challenge}s returned. However, this
     * method attempts to find the combination with the smallest number of
     * {@link Challenge}s.
     *
     * @param types
     *            Challenge name or names (e.g. "http-01"), in no particular order.
     *            Basically this is a collection of all challenge types supported by your
     *            implementation.
     * @return Matching {@link Challenge} combination, or an empty collection if the ACME
     *         server does not support any of your challenges. The challenges are returned
     *         in no particular order. The result may be a subset of the types you have
     *         provided, if fewer challenges are actually required for a successful
     *         validation.
     */
    public Collection<Challenge> findCombination(String... types) {
        Collection<String> available = Arrays.asList(types);
        Collection<String> combinationTypes = new ArrayList<>();

        Collection<Challenge> result = Collections.emptyList();

        for (List<Challenge> combination : getCombinations()) {
            combinationTypes.clear();
            for (Challenge c : combination) {
                combinationTypes.add(c.getType());
            }

            if (available.containsAll(combinationTypes) &&
                    (result.isEmpty() || result.size() > combination.size())) {
                result = combination;
            }
        }

        return Collections.unmodifiableCollection(result);
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
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);

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
            claims.putResource("authz");
            claims.put("status", "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getSession());
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);
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
                throw new AcmeProtocolException("Could not load lazily", ex);
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
        this.status = Status.parse(json.get("status").asString(), Status.PENDING);

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
        combinations = fetchCombinations(json, challenges);

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
        JSON.Array jsonChallenges = json.get("challenges").asArray();
        List<Challenge> cr = new ArrayList<>();
        for (JSON.Value c : jsonChallenges) {
            Challenge ch = getSession().createChallenge(c.asObject());
            if (ch != null) {
                cr.add(ch);
            }
        }
        return cr;
    }

    /**
     * Fetches all possible combination of {@link Challenge} that are defined in the JSON.
     *
     * @param json
     *            {@link JSON} to read
     * @param challenges
     *            List of available {@link Challenge}
     * @return List of {@link Challenge} combinations
     */
    private List<List<Challenge>> fetchCombinations(JSON json, List<Challenge> challenges) {
        JSON.Array jsonCombinations = json.get("combinations").asArray();
        if (jsonCombinations == null) {
            return Arrays.asList(challenges);
        }

        List<List<Challenge>> cmb = new ArrayList<>(jsonCombinations.size());
        for (JSON.Value v : jsonCombinations) {
            JSON.Array c = v.asArray();
            List<Challenge> clist = new ArrayList<>(c.size());
            for (JSON.Value n : c) {
                clist.add(challenges.get(n.asInt()));
            }
            cmb.add(clist);
        }
        return cmb;
    }

}
