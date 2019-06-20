/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.model;

import static java.util.stream.Collectors.toList;

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.AuthorizationController;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A mock authorization.
 * <p>
 * It reflects the server side of {@link org.shredzone.acme4j.Authorization} objects.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockAuthorization extends MockResource {
    private final Identifier identifier;
    private final List<MockChallenge> challenges = new ArrayList<>();

    private Status status;
    private Instant expires;
    private Boolean wildcard;

    /**
     * Internal constructor. Use {@link MockAuthorization#create(Repository, Identifier)}.
     */
    private MockAuthorization(Identifier identifier) {
        this.identifier = identifier;
    }

    /**
     * Creates a new {@link MockAuthorization} instance.
     *
     * @param repository
     *         {@link Repository} to add the resource to
     * @param identifier
     *         {@link Identifier} to be authorized
     * @return The generated {@link MockAuthorization}
     */
    public static MockAuthorization create(Repository repository, Identifier identifier) {
        MockAuthorization auth = new MockAuthorization(identifier);
        repository.addResource(auth, AuthorizationController::new);
        return auth;
    }

    /**
     * Returns the {@link Identifier} to be authorized.
     */
    public Identifier getIdentifier() {
        return identifier;
    }

    /**
     * Returns the current status.
     * <p>
     * If no concrete status was set via {@link #setStatus(Status)}, the mock resource
     * tries to deduce a reasonable status from its current state.
     */
    public Status getStatus() {
        if (status != null) {
            return status;
        }

        if (expires != null && expires.isBefore(Instant.now())) {
            return Status.EXPIRED;
        }

        if (challenges.stream().map(MockChallenge::getStatus).anyMatch(s -> s == Status.VALID)) {
            return Status.VALID;
        }

        if (challenges.stream().map(MockChallenge::getStatus).anyMatch(s -> s == Status.INVALID)) {
            return Status.INVALID;
        }

        return Status.PENDING;
    }

    /**
     * Sets the current status.
     *
     * @param status
     *         new {@link Status}, or {@code null} to clear the status and let the
     *         resource decide on its current status automatically.
     */
    public void setStatus(@Nullable Status status) {
        this.status = status;
    }

    /**
     * Returns the expiration date. {@code null} if no date was set.
     */
    @CheckForNull
    public Instant getExpires() {
        return expires;
    }

    /**
     * Sets the expiration date.
     *
     * @param expires
     *         {@link Instant} of expiration, or {@code null} if undefined
     */
    public void setExpires(@Nullable Instant expires) {
        this.expires = expires;
    }

    /**
     * Returns a list of {@link MockChallenge} that need to be performed for
     * authorization.
     *
     * @return List of MockChallenge objects. The list can be modified.
     */
    public List<MockChallenge> getChallenges() {
        return challenges;
    }

    /**
     * Returns whether this is a wildcard authorization. {@code null} if undefined.
     */
    @CheckForNull
    public Boolean getWildcard() {
        return wildcard;
    }

    /**
     * Sets whether this is a wildcard authorization.
     *
     * @param wildcard
     *         Wildcard authorization, {@code null} means undefined.
     */
    public void setWildcard(@Nullable Boolean wildcard) {
        this.wildcard = wildcard;
    }

    @Override
    public URL getLocation() {
        return buildUrl("authz", getUniqueId());
    }

    @Override
    public JSON toJSON() {
        JSONBuilder jb = new JSONBuilder();
        jb.put("identifier", getIdentifier().toMap());
        jb.put("status", getStatus().name().toLowerCase());
        if (getExpires() != null) {
            jb.put("expires", getExpires());
        }
        jb.array("challenges", getChallenges().stream()
                .map(MockChallenge::toJSON)
                .map(JSON::toMap)
                .collect(toList())
        );
        if (Boolean.TRUE.equals(getWildcard())) {
            // wildcard must only be present if true!
            jb.put("wildcard", true);
        }
        return jb.toJSON();
    }

}
