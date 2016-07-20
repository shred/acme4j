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
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Contains metadata related to the provider.
 *
 * @author Richard "Shred" Körber
 */
public class Metadata {

    private final Map<String, Object> meta;

    /**
     * Creates an empty new {@link Metadata} instance.
     */
    public Metadata() {
        this(new HashMap<String, Object>());
    }

    /**
     * Creates a new {@link Metadata} instance.
     *
     * @param meta
     *            JSON map of metadata
     */
    public Metadata(Map<String, Object> meta) {
        this.meta = meta;
    }

    /**
     * Returns an {@link URI} to the current terms of service, or {@code null} if not
     * available.
     */
    public URI getTermsOfService() {
        return getUri("terms-of-service");
    }

    /**
     * Returns an {@link URI} to a website providing more information about the ACME
     * server. {@code null} if not available.
     */
    public URI getWebsite() {
        return getUri("website");
    }

    /**
     * Returns an array of hostnames, which the ACME server recognises as referring to
     * itself for the purposes of CAA record validation. {@code null} if not available.
     */
    public String[] getCaaIdentities() {
        return getStringArray("caa-identities");
    }

    /**
     * Gets a custom metadata value, as {@link String}.
     *
     * @param key
     *            Key of the meta value
     * @return Value as {@link String}, or {@code null} if there is no such key in the
     *         directory metadata.
     */
    public String get(String key) {
        Object value = meta.get(key);
        return (value != null ? value.toString() : null);
    }

    /**
     * Gets a custom metadata value, as {@link URI}.
     *
     * @param key
     *            Key of the meta value
     * @return Value as {@link URI}, or {@code null} if there is no such key in the
     *         directory metadata.
     * @throws AcmeProtocolException
     *             if the value is not an {@link URI}
     */
    public URI getUri(String key) {
        Object uri = meta.get(key);
        try {
            return (uri != null ? new URI(uri.toString()) : null);
        } catch (URISyntaxException ex) {
            throw new AcmeProtocolException("Bad URI: " + uri, ex);
        }
    }

    /**
     * Gets a custom metadata value, as array of {@link String}.
     *
     * @param key
     *            Key of the meta value
     * @return {@link String} array, or {@code null} if there is no such key in the
     *         directory metadata.
     */
    @SuppressWarnings("unchecked")
    public String[] getStringArray(String key) {
        Object value = meta.get(key);
        if (value != null && value instanceof Collection) {
            Collection<String> data = (Collection<String>) value;
            return data.toArray(new String[data.size()]);
        }
        return null;
    }

    /**
     * Returns the metadata as raw JSON map.
     * <p>
     * Do not modify the map or its contents. Changes will have a session-wide effect.
     */
    public Map<String, Object> getJsonData() {
        return meta;
    }

}
