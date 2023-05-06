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

import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;

/**
 * A collection of metadata related to the CA provider.
 */
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
     * Returns an {@link URI} of the current terms of service, or empty if not available.
     */
    public Optional<URI> getTermsOfService() {
        return meta.get("termsOfService").map(Value::asURI);
    }

    /**
     * Returns an {@link URL} of a website providing more information about the ACME
     * server. Empty if not available.
     */
    public Optional<URL> getWebsite() {
        return meta.get("website").map(Value::asURL);
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
     * Returns whether the CA supports short-term auto-renewal of certificates.
     *
     * @since 2.3
     */
    public boolean isAutoRenewalEnabled() {
        return meta.get("auto-renewal").isPresent();
    }

    /**
     * Returns the minimum acceptable value for the maximum validity of a certificate
     * before auto-renewal. Empty if the CA does not support short-term auto-renewal.
     *
     * @since 2.3
     */
    public Optional<Duration> getAutoRenewalMinLifetime() {
        return meta.get("auto-renewal").optional().map(Value::asObject)
                .map(j -> j.get("min-lifetime"))
                .map(Value::asDuration);
    }

    /**
     * Returns the maximum delta between auto-renewal end date and auto-renewal start
     * date.
     *
     * @since 2.3
     */
    public Optional<Duration> getAutoRenewalMaxDuration() {
        return meta.get("auto-renewal").optional().map(Value::asObject)
                .map(j -> j.get("max-duration"))
                .map(Value::asDuration);
    }

    /**
     * Returns whether the CA also allows to fetch STAR certificates via GET request.
     *
     * @since 2.6
     */
    public boolean isAutoRenewalGetAllowed() {
        return meta.get("auto-renewal").optional().map(Value::asObject)
                .map(j -> j.get("allow-certificate-get"))
                .map(Value::asBoolean)
                .orElse(false);
    }

    /**
     * Returns the JSON representation of the metadata. This is useful for reading
     * proprietary metadata properties.
     */
    public JSON getJSON() {
        return meta;
    }

}
