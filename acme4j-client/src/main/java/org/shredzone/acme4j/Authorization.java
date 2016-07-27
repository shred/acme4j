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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TimestampParser;
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
    private Date expires;
    private List<Challenge> challenges;
    private List<List<Challenge>> combinations;
    private boolean loaded = false;

    /**
     * Creates a new instance of {@link Authorization} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location of the Authorization
     */
    public static Authorization bind(Session session, URI location) {
        return new Authorization(session, location);
    }

    protected Authorization(Session session, URI location) {
        super(session);
        setLocation(location);
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
    public Date getExpires() {
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
     *         challenge, or the challenge alone is not sufficient for authorization.
     * @throws ClassCastException
     *             if the type does not match the expected Challenge class type
     */
    @SuppressWarnings("unchecked")
    public <T extends Challenge> T findChallenge(String type) {
        Collection<Challenge> result = findCombination(type);
        return (result != null ? (T) result.iterator().next() : null);
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
     * @return Matching {@link Challenge} combination, or {@code null} if the ACME server
     *         does not support any of your challenges. The challenges are returned in no
     *         particular order. The result may be a subset of the types you have
     *         provided, if fewer challenges are actually required for a successful
     *         validation.
     */
    public Collection<Challenge> findCombination(String... types) {
        if (getCombinations() == null) {
            return null;
        }

        Collection<String> available = Arrays.asList(types);
        Collection<String> combinationTypes = new ArrayList<>();

        Collection<Challenge> result = null;

        for (List<Challenge> combination : getCombinations()) {
            combinationTypes.clear();
            for (Challenge c : combination) {
                combinationTypes.add(c.getType());
            }

            if (available.containsAll(combinationTypes) &&
                    (result == null || result.size() > combination.size())) {
                result = combination;
            }
        }

        return result;
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
            int rc = conn.sendRequest(getLocation());
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            Map<String, Object> result = conn.readJsonResponse();
            unmarshalAuthorization(result);

            if (rc == HttpURLConnection.HTTP_ACCEPTED) {
                Date retryAfter = conn.getRetryAfterHeader();
                if (retryAfter != null) {
                    throw new AcmeRetryAfterException(
                                    "authorization is not completed yet",
                                    retryAfter);
                }
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Permanently deactivates the {@link Authorization}.
     */
    public void deactivate() throws AcmeException {
        LOG.debug("deactivate");
        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("authz");
            claims.put("status", "deactivated");

            int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
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
    @SuppressWarnings("unchecked")
    protected void unmarshalAuthorization(Map<String, Object> json) {
        this.status = Status.parse((String) json.get("status"), Status.PENDING);

        String expires = (String) json.get("expires");
        if (expires != null) {
            this.expires = TimestampParser.parse(expires);
        }

        Map<String, Object> identifier = (Map<String, Object>) json.get("identifier");
        if (identifier != null) {
            String type = (String) identifier.get("type");
            if (type != null && !"dns".equals(type)) {
                throw new AcmeProtocolException("Unknown authorization type: " + type);
            }
            this.domain = (String) identifier.get("value");
        }

        Collection<Map<String, Object>> challenges =
                        (Collection<Map<String, Object>>) json.get("challenges");
        List<Challenge> cr = new ArrayList<>();
        for (Map<String, Object> c : challenges) {
            Challenge ch = getSession().createChallenge(c);
            if (ch != null) {
                cr.add(ch);
            }
        }
        this.challenges = cr;

        Collection<List<Number>> combinations =
                        (Collection<List<Number>>) json.get("combinations");
        if (combinations != null) {
            List<List<Challenge>> cmb = new ArrayList<>(combinations.size());
            for (List<Number> c : combinations) {
                List<Challenge> clist = new ArrayList<>(c.size());
                for (Number n : c) {
                    clist.add(cr.get(n.intValue()));
                }
                cmb.add(clist);
            }
            this.combinations = cmb;
        } else {
            List<List<Challenge>> cmb = new ArrayList<>(1);
            cmb.add(cr);
            this.combinations = cmb;
        }

        loaded = true;
    }

}
