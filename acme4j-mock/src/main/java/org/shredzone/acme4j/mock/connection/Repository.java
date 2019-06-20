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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.mock.controller.ControllerWrapper;
import org.shredzone.acme4j.mock.model.MockResource;

/**
 * This is a repository of all {@link Controller} and {@link MockResource} instances of
 * a mock server. It is also used to resolve request {@link URL}.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class Repository {
    // Do not use URL as key! URL#equals() is expensive and connects to the internet.
    private final Map<URI, Controller> resourceMap = new HashMap<>();
    private final Map<URI, MockResource> resources = new HashMap<>();

    /**
     * Adds a generic {@link Controller} to this repository.
     *
     * @param address
     *         {@link URL} to be added
     * @param controller
     *         {@link Controller} instance to be invoked
     */
    public void addController(URL address, Controller controller) {
        URI uri = safeToURI(address);
        if (resourceMap.containsKey(uri)) {
            throw new IllegalArgumentException("Address " + address + " is already in use");
        }
        resourceMap.put(uri, controller);
    }

    /**
     * Returns the {@link Controller} instance for the given {@link URL}.
     *
     * @param url
     *         Resource {@link URL} to get the {@link Controller} instance of.
     * @return Controller
     */
    public Optional<Controller> getController(URL url) {
        return Optional.ofNullable(resourceMap.get(safeToURI(url)));
    }

    /**
     * Wraps an existing controller. The wrapping controller will be invoked instead of
     * the original controller.
     *
     * @param url
     *         {@link URL} of the resource to be wrapped
     * @param wrapperFactory
     *         A {@link Function} that receives the {@link Controller} that is currently
     *         registered, and returns a new {@link Controller} instance that is to
     *         be used instead.
     * @see ControllerWrapper
     */
    public void wrapController(URL url, Function<Controller, Controller> wrapperFactory) {
        URI uri = safeToURI(url);
        Controller receiver = resourceMap.get(uri);
        if (receiver == null) {
            throw new IllegalArgumentException("No controller is registered for " + url);
        }
        resourceMap.put(uri, wrapperFactory.apply(receiver));
    }

    /**
     * Adds a {@link MockResource} to this repository.
     *
     * @param resource
     *         {@link MockResource} to be added
     * @param builder
     *         A {@link Function} that creates a {@link Controller} for this resource
     */
    public <R extends MockResource> void addResource(R resource, Function<R, Controller> builder) {
        addController(resource.getLocation(), builder.apply(resource));
        resources.put(safeToURI(resource.getLocation()), resource);
    }

    /**
     * Gets the {@link MockResource} of the given type, for the given {@link URL}.
     *
     * @param url
     *         {@link URL} of the {@link MockResource}
     * @param type
     *         Expected {@link MockResource} type
     * @return The {@link MockResource} behind the {@link URL}
     */
    public <R extends MockResource> Optional<R> getResourceOfType(URL url, Class<R> type) {
        return Optional.ofNullable(resources.get(safeToURI(url)))
                .filter(type::isInstance)
                .map(type::cast);
    }

    /**
     * Safely converts an {@link URL} to an {@link URI}.
     *
     * @param url
     *         {@link URL} to convert
     * @return Converted {@link URI}
     */
    private static URI safeToURI(URL url) {
        try {
            return url.toURI();
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Illegal URL: " + url, ex);
        }
    }

}
