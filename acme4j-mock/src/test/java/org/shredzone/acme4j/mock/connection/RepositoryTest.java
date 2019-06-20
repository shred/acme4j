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

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.mock.controller.ControllerWrapper;
import org.shredzone.acme4j.mock.model.MockResource;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Unit tests for {@link Repository}.
 */
public class RepositoryTest {

    /**
     * Test handling of {@link Controller}.
     */
    @Test
    public void testControllers() throws MalformedURLException {
        URL url = new URL("https://mock.test/nop");
        Controller controller = new Controller() {};

        Repository repository = new Repository();

        assertThat(repository.getController(url).isPresent(), is(false));

        repository.addController(url, controller);

        assertThat(repository.getController(url).isPresent(), is(true));
        assertThat(repository.getController(url).get(), sameInstance(controller));

        try {
            repository.addController(url, controller);
            fail("Could add controller again");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test handling of {@link MockResource}.
     */
    @Test
    public void testResources() throws MalformedURLException {
        URL url = new URL("https://mock.test/nop");
        Controller controller = new Controller() {};
        MockResource resource = new MockResource() {
            @Override
            public URL getLocation() {
                return url;
            }

            @Override
            public JSON toJSON() {
                return JSON.empty();
            }
        };

        Repository repository = new Repository();

        assertThat(repository.getResourceOfType(url, MockResource.class).isPresent(), is(false));
        assertThat(repository.getController(url).isPresent(), is(false));

        repository.addResource(resource, r -> controller);

        assertThat(repository.getResourceOfType(url, MockResource.class).isPresent(), is(true));
        assertThat(repository.getResourceOfType(url, MockResource.class).get(), sameInstance(resource));
        assertThat(repository.getController(url).isPresent(), is(true));
        assertThat(repository.getController(url).get(), sameInstance(controller));

        try {
            repository.addResource(resource, r -> controller);
            fail("Could add resource again");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test controller wrapping.
     */
    @Test
    public void testWrapper() throws MalformedURLException {
        URL url = new URL("https://mock.test/nop");
        Controller controller = new Controller() {};
        Controller wrapper = new ControllerWrapper<Controller>(controller) {};

        Repository repository = new Repository();
        repository.addController(url, controller);
        assertThat(repository.getController(url).get(), sameInstance(controller));

        repository.wrapController(url, old -> {
            assertThat(old, sameInstance(controller));
            return wrapper;
        });

        assertThat(repository.getController(url).isPresent(), is(true));
        assertThat(repository.getController(url).get(), sameInstance(wrapper));
    }

}
