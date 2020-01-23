/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.Collection;
import java.util.Optional;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;

/**
 * Contains metadata related to the provider.
 */
@ParametersAreNonnullByDefault
@Immutable
public class Metadata {

    private final JSON meta;

    /**
     * Creates a new {@link Metadata} instance.
     *
     * @param meta
     *            JSON map of metadata
     */
    public Metadata(JSON meta) {
        this.meta = meta;
    }

    /**
     * Returns an {@link URI} to the current terms of service, or {@code null} if not
     * available.
     */
    @CheckForNull
    public URI getTermsOfService() {
        return meta.get("termsOfService").map(Value::asURI).orElse(null);
    }

    /**
     * Returns an {@link URL} to a website providing more information about the ACME
     * server. {@code null} if not available.
     */
    @CheckForNull
    public URL getWebsite() {
        return meta.get("website").map(Value::asURL).orElse(null);
    }

    /**
     * Returns a collection of hostnames, which the ACME server recognises as referring to
     * itself for the purposes of CAA record validation. Empty if not available.
     */
    public Collection<String> getCaaIdentities() {
        return meta.get("caaIdentities")
                .asArray()
                .stream()
                .map(Value::asString)
                .collect(toList());
    }

    /**
     * Returns whether an external account is required by this CA.
     */
    public boolean isExternalAccountRequired() {
        return meta.get("externalAccountRequired").map(Value::asBoolean).orElse(false);
    }

    /**
     * Returns whether the CA supports short-term auto renewal of certificates.
     *
     * @since 2.3
     */
    public boolean isAutoRenewalEnabled() {
        return meta.get("auto-renewal").isPresent();
    }

    /**
     * Returns the minimum acceptable value for the maximum validity of a certificate
     * before auto renewal. {@code null} if the CA does not support short-term auto
     * renewal.
     *
     * @since 2.3
     */
    public Duration getAutoRenewalMinLifetime() {
        Optional<JSON> ar = meta.get("auto-renewal").optional().map(Value::asObject);
        if (!ar.isPresent()) {
            return null;
        }
        return ar.get().get("min-lifetime").map(Value::asDuration).orElse(null);
    }

    /**
     * Returns the maximum delta between auto-renewal end date and auto-renewal start
     * date. {@code null} if the CA does not support short-term auto renewal.
     *
     * @since 2.3
     */
    public Duration getAutoRenewalMaxDuration() {
        Optional<JSON> ar = meta.get("auto-renewal").optional().map(Value::asObject);
        if (!ar.isPresent()) {
            return null;
        }
        return ar.get().get("max-duration").map(Value::asDuration).orElse(null);
    }

    /**
     * Returns whether the CA also allows to fetch STAR certificates via GET request.
     *
     * @since 2.6
     */
    public boolean isAutoRenewalGetAllowed() {
        Optional<JSON> ar = meta.get("auto-renewal").optional().map(Value::asObject);
        if (!ar.isPresent()) {
            return false;
        }
        return ar.get().get("allow-certificate-get").map(Value::asBoolean).orElse(false);
    }

    /**
     * Returns the JSON representation of the metadata. This is useful for reading
     * proprietary metadata properties.
     */
    public JSON getJSON() {
        return meta;
    }

}
