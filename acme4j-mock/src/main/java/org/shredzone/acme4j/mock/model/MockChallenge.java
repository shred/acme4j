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

import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.ChallengeController;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A mock challenge.
 * <p>
 * It reflects the server side of {@link org.shredzone.acme4j.challenge.Challenge}
 * objects.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockChallenge extends MockResource {
    private static final Random RND = new Random();

    private final String type;
    private final Map<String, Object> data = new HashMap<>();

    private Status status;
    private Instant validated;
    private Problem error;
    private String token;

    /**
     * Internal constructor. Use {@link MockChallenge#create(Repository, String)}.
     */
    private MockChallenge(String type) {
        this.type = type;
    }

    /**
     * Creates a new {@link MockChallenge} instance.
     *
     * @param repository
     *         {@link Repository} to add the resource to
     * @param type
     *         Challenge type (e.g. {@value org.shredzone.acme4j.challenge.Http01Challenge#TYPE}).
     * @return The generated {@link MockChallenge}
     */
    public static MockChallenge create(Repository repository, String type) {
        MockChallenge challenge = new MockChallenge(type);
        repository.addResource(challenge, ChallengeController::new);
        return challenge;
    }

    /**
     * Returns the type of this challenge.
     */
    public String getType() {
        return type;
    }

    /**
     * Returns the current challenge status.
     * <p>
     * If no concrete status was set via {@link #setStatus(Status)}, the mock resource
     * tries to deduce a reasonable status from its current state.
     */
    public Status getStatus() {
        if (status != null) {
            return status;
        }

        if (getError() != null) {
            return Status.INVALID;
        }

        if (getValidated() != null) {
            return Status.VALID;
        }

        return Status.PENDING;
    }

    /**
     * Sets the current challenge status.
     *
     * @param status
     *         new {@link Status}, or {@code null} to clear the status and let the
     *         resource decide on its current status automatically.
     */
    public void setStatus(@Nullable Status status) {
        this.status = status;
    }

    /**
     * Returns the validation {@link Instant}, or {@code null} if unknown.
     */
    @CheckForNull
    public Instant getValidated() {
        return validated;
    }

    /**
     * Sets the validation {@link Instant}.
     *
     * @param validated
     *         Validation {@link Instant}, {@code null} if undefined.
     */
    public void setValidated(@Nullable Instant validated) {
        this.validated = validated;
    }

    /**
     * Returns the {@link Problem} why a validation has failed. {@code null} if there was
     * no problem.
     */
    @CheckForNull
    public Problem getError() {
        return error;
    }

    /**
     * Sets the {@link Problem} why a validation has failed.
     *
     * @param error
     *         {@link Problem} that caused the failure. {@code null} if there was no
     *         error.
     */
    public void setError(@Nullable Problem error) {
        this.error = error;
    }

    /**
     * Returns the token that is used in this challenge. Only used for token based
     * challenges, {@code null} otherwise.
     */
    @CheckForNull
    public String getToken() {
        return token;
    }

    /**
     * Sets the token that is used in this challenge. Only used for token based
     * challenges.
     *
     * @param token
     *         Token to be used.
     */
    public void setToken(@Nullable String token) {
        this.token = token;
    }

    /**
     * Returns a Map for custom challenge attributes. Can be modified to test custom
     * challenges having attributes that are not defined in RFC 8555.
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * Sets a new random token for token-based challenges.
     */
    public void setRandomToken() {
        byte[] newToken = new byte[16];
        RND.nextBytes(newToken);
        setToken(AcmeUtils.base64UrlEncode(newToken));
    }

    @Override
    public URL getLocation() {
        return buildUrl("challenge", getUniqueId());
    }

    @Override
    public JSON toJSON() {
        JSONBuilder jb = new JSONBuilder();
        jb.put("type", getType());
        jb.put("url", getLocation());
        jb.put("status", getStatus().name().toLowerCase());
        if (getValidated() != null) {
            jb.put("validated", getValidated());
        }
        Problem pb = getError();
        if (pb != null) {
            jb.put("error", pb.asJSON().toMap());
        }
        if (getToken() != null) {
            jb.put("token", getToken());
        }
        getData().forEach(jb::put);

        return jb.toJSON();
    }

}
