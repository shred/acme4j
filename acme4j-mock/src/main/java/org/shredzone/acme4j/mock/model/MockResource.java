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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.UUID;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.toolbox.JSON;

/**
 * A generic mock resource.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public abstract class MockResource {
    private static final URI BASE_URI = URI.create("https://acme.test/");

    private final String id = UUID.randomUUID().toString();

    /**
     * Returns the location of the mocked resource.
     * <p>
     * Locations may have a random part. Never make assumptions about the structure of a
     * location URL.
     */
    public abstract URL getLocation();

    /**
     * Generates a {@link JSON} object of the current resource state.
     */
    public abstract JSON toJSON();

    /**
     * Returns the internal ID of this resource. This is a random value that is unique
     * to this resource.
     */
    public String getUniqueId() {
        return id;
    }

    @Override
    public String toString() {
        return getLocation() + ": " +toJSON();
    }

    /**
     * Builds an {@link URL} from the given path components.
     *
     * @param path
     *         Elements of the URL path
     * @return Fake https URL that refers to a mock server and contains the path elements
     */
    protected static URL buildUrl(String... path) {
        try {
            return BASE_URI.resolve(String.join("/", path)).toURL();
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}
