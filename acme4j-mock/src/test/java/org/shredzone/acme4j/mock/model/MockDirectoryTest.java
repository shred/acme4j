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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.mock.controller.DirectoryController;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link MockDirectory}.
 */
public class MockDirectoryTest {
    private static final Controller NOP_CONTROLLER = new Controller() {};
    private static final Map<String, Controller> TYPE_MAP = Collections.singletonMap("test", NOP_CONTROLLER);

    /**
     * Test creation and default values.
     */
    @Test
    public void testCreate() {
        Repository repository = new Repository();
        MockDirectory dir = MockDirectory.create(repository, TYPE_MAP);

        // Check locations
        assertThat(dir.getUniqueId(), not(emptyOrNullString()));
        assertThat(dir.getLocation().toString(),
                is("https://acme.test/directory"));

        // Controllers were added to the repository?
        assertThat(repository.getController(dir.getLocation()).get(),
                is(instanceOf(DirectoryController.class)));
        assertThat(repository.getResourceOfType(dir.getLocation(), MockDirectory.class).get(),
                is(sameInstance(dir)));

        // Check Endpoints
        Map<String, URL> endpoints = dir.getEndpoints();
        assertThat(endpoints.size(), is(1));
        assertThat(endpoints.get("test"), not(nullValue()));
        URL testUrl = endpoints.get("test");

        assertThat(repository.getController(testUrl).get(), is(sameInstance(NOP_CONTROLLER)));

        // Default values
        assertThat(dir.getMetadata(), is(anEmptyMap()));
    }

    /**
     * Test setters and JSON generation.
     */
    @Test
    public void testSettersAndJson() {
        Repository repository = new Repository();
        MockDirectory dir = MockDirectory.create(repository, TYPE_MAP);

        dir.getMetadata().put("foo", 123);

        assertThat(dir.getMetadata().size(), is(1));
        assertThat(dir.getMetadata().get("foo"), is(123));

        JSONBuilder jb = new JSONBuilder();
        jb.put("test", dir.getEndpoints().get("test"));
        jb.object("meta").put("foo", 123);
        assertThat(dir.toJSON().toString(), sameJSONAs(jb.toString()));
    }

}