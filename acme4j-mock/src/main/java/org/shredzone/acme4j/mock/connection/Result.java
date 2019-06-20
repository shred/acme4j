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
package org.shredzone.acme4j.mock.connection;

import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

import org.shredzone.acme4j.mock.model.MockResource;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Contains the result of a request.
 * <p>
 * Results are immutable.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
@Immutable
public final class Result {
    private static final Result EMPTY = new Result();

    private final JSON json;
    private final URL location;
    private final Instant retryAfter;
    private final List<X509Certificate> certificate;

    /**
     * Creates an empty Result.
     */
    private Result() {
        this.json = null;
        this.location = null;
        this.retryAfter = null;
        this.certificate = null;
    }

    /**
     * Creates a new JSON type result for the given {@link MockResource}.
     *
     * @param resource
     *         {@link MockResource} to use the JSON body and location URL from
     */
    public Result(MockResource resource) {
        this(resource.toJSON(), resource.getLocation());
    }

    /**
     * Creates a new JSON type result.
     *
     * @param json
     *         {@link JSON} result body
     */
    public Result(JSON json) {
        this(json, null, null);
    }

    /**
     * Creates a new JSON type result.
     *
     * @param json
     *         {@link JSON} result body
     * @param location
     *         Location header
     */
    public Result(JSON json, URL location) {
        this(json, location, null);
    }

    /**
     * Creates a new JSON type result.
     *
     * @param json
     *         {@link JSON} result body
     * @param location
     *         Location header, or {@code null} if there is none
     * @param retryAfter
     *         Instant of Retry-After header, or {@code null} if there is none
     */
    public Result(JSON json, @Nullable URL location, @Nullable Instant retryAfter) {
        this.json = requireNonNull(json, "json");
        this.location = location;
        this.retryAfter = retryAfter;
        this.certificate = null;
    }

    /**
     * Creates a Certificate type result.
     *
     * @param certificate
     *         Certificate chain
     */
    public Result(List<X509Certificate> certificate) {
        this.certificate = unmodifiableList(new ArrayList<>(requireNonNull(certificate, "certificate")));
        this.json = null;
        this.location = null;
        this.retryAfter = null;
    }

    /**
     * Returns the {@link JSON} result. {@code null} if this is an empty or a certificate
     * result.
     */
    @CheckForNull
    public JSON getJSON() {
        return json;
    }

    /**
     * Returns a certificate chain result. {@code null} if this is an empty or a JSON
     * result.
     */
    @CheckForNull
    public List<X509Certificate> getCertificate() {
        return certificate;
    }

    /**
     * Returns the location header, or {@code null} if not set.
     */
    @CheckForNull
    public URL getLocation() {
        return location;
    }

    /**
     * Returns the Retry-After header, or {@code null} if not set.
     */
    @CheckForNull
    public Instant getRetryAfter() {
        return retryAfter;
    }

    /**
     * Creates a new {@link Result} with the given {@link Instant} used as Retry-After
     * header. If a Retry-After header was already set, it will be replaced.
     * <p>
     * Retry-After headers are only acceptable on JSON results.
     *
     * @param instant
     *         {@link Instant} of Retry-After header
     * @return New {@link Result} with the Retry-After header set.
     */
    public Result withRetryAfter(Instant instant) {
        if (json == null) {
            throw new IllegalStateException("Cannot set a Retry-After header on this result type");
        }
        return new Result(json, location, instant);
    }

    /**
     * Returns an empty result.
     */
    public static Result empty() {
        return EMPTY;
    }

}
