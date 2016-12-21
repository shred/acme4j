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

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSON.Array;
import org.shredzone.acme4j.util.JSON.Value;

/**
 * Contains metadata related to the provider.
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
     * Returns an {@link URI} to the current terms of service, or {@code null} if not
     * available.
     */
    public URI getTermsOfService() {
        return meta.get("terms-of-service").asURI();
    }

    /**
     * Returns an {@link URI} to a website providing more information about the ACME
     * server. {@code null} if not available.
     */
    public URI getWebsite() {
        return meta.get("website").asURI();
    }

    /**
     * Returns a collection of hostnames, which the ACME server recognises as referring to
     * itself for the purposes of CAA record validation. {@code null} if not available.
     */
    public Collection<String> getCaaIdentities() {
        Array array = meta.get("caa-identities").asArray();
        if (array == null) {
            return null;
        }

        List<String> result = new ArrayList<>(array.size());
        for (Value v : array) {
            result.add(v.asString());
        }
        return result;
    }

    /**
     * Returns the JSON representation of the metadata. This is useful for reading
     * proprietary metadata properties.
     */
    public JSON getJSON() {
        return meta;
    }

}
