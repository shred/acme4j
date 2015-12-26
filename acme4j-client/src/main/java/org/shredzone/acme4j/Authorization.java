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

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.shredzone.acme4j.challenge.Challenge;

/**
 * Represents an authorization request at the ACME server.
 *
 * @author Richard "Shred" Körber
 */
public class Authorization implements Serializable {
    private static final long serialVersionUID = -3116928998379417741L;

    private URI location;
    private String domain;
    private Status status;
    private Date expires;
    private List<Challenge> challenges;
    private List<List<Challenge>> combinations;

    /**
     * Create an empty {@link Authorization}.
     */
    public Authorization() {
        // default constructor
    }

    /**
     * Create an {@link Authorization} for the given location URI.
     */
    public Authorization(URI location) {
        this.location = location;
    }

    /**
     * Gets the server URI for the authorization.
     */
    public URI getLocation() {
        return location;
    }

    /**
     * Sets the server URI for the authorization.
     */
    public void setLocation(URI location) {
        this.location = location;
    }

    /**
     * Gets the domain name to be authorized.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Sets the domain name to authorize.
     */
    public void setDomain(String domain) {
        this.domain = domain;
    }

    /**
     * Gets the authorization status.
     */
    public Status getStatus() {
        return status;
    }

    /**
     * Sets the authorization status.
     */
    public void setStatus(Status status) {
        this.status = status;
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Date getExpires() {
        return expires;
    }

    /**
     * Sets the expiry date of the authorization.
     */
    public void setExpires(Date expires) {
        this.expires = expires;
    }

    /**
     * Gets a list of all challenges available by the server.
     */
    public List<Challenge> getChallenges() {
        return challenges;
    }

    /**
     * Sets a list of all challenges available by the server.
     */
    public void setChallenges(List<Challenge> challenges) {
        this.challenges = challenges;
    }

    /**
     * Gets all combinations of challenges supported by the server.
     */
    public List<List<Challenge>> getCombinations() {
        return combinations;
    }

    /**
     * Sets all combinations of challenges supported by the server.
     */
    public void setCombinations(List<List<Challenge>> combinations) {
        this.combinations = combinations;
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
        if (combinations == null) {
            return null;
        }

        Collection<String> available = Arrays.asList(types);
        Collection<String> combinationTypes = new ArrayList<>();

        Collection<Challenge> result = null;

        for (List<Challenge> combination : combinations) {
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

}
