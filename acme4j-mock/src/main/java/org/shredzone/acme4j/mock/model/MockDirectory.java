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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.mock.controller.DirectoryController;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * A mock ACME server directory.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockDirectory extends MockResource {
    private final Map<String, URL> endpoints;
    private final Map<String, Object> metadata = new HashMap<>();

    /**
     * Internal constructor. Use {@link MockDirectory#create(Repository, Map)}
     */
    private MockDirectory(Map<String, URL> endpoints) {
        this.endpoints = Collections.unmodifiableMap(endpoints);
    }

    /**
     * Creates a new {@link MockDirectory} instance.
     *
     * @param repository
     *         {@link Repository} to add the resource to
     * @param typeMap
     *         Map of directory types, and {@link Controller} instances handling that
     *         type.
     * @return The generated {@link MockDirectory}
     */
    public static MockDirectory create(Repository repository, Map<String, Controller> typeMap) {
        Map<String, URL> endpoints = new HashMap<>();
        typeMap.forEach((t, c) -> {
            URL url = buildUrl("do", t);
            endpoints.put(t, url);
            repository.addController(url, c);
        });
        MockDirectory directory = new MockDirectory(endpoints);
        repository.addResource(directory, DirectoryController::new);
        return directory;
    }

    /**
     * Gets a map of all defined endpoints. This map is unmodifiable.
     */
    public Map<String, URL> getEndpoints() {
        return endpoints;
    }

    /**
     * Gets a map of all metadata. This map may be modified at will.
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    @Override
    public URL getLocation() {
        return buildUrl("directory");
    }

    @Override
    public JSON toJSON() {
        JSONBuilder jb = new JSONBuilder();
        getEndpoints().forEach(jb::put);
        if (!getMetadata().isEmpty()) {
            jb.put("meta", getMetadata());
        }
        return jb.toJSON();
    }

}
