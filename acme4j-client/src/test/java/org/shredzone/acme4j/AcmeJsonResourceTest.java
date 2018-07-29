/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.*;

import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AcmeJsonResource}.
 */
public class AcmeJsonResourceTest {

    private static final JSON JSON_DATA = getJSON("newAccountResponse");
    private static final URL LOCATION_URL = url("https://example.com/acme/resource/123");

    /**
     * Test {@link AcmeJsonResource#AcmeJsonResource(Login, URL)}.
     */
    @Test
    public void testLoginConstructor() {
        Login login = TestUtils.login();

        AcmeJsonResource resource = new DummyJsonResource(login, LOCATION_URL);
        assertThat(resource.getLogin(), is(login));
        assertThat(resource.getSession(), is(login.getSession()));
        assertThat(resource.getLocation(), is(LOCATION_URL));
        assertThat(resource.isValid(), is(false));
        assertUpdateInvoked(resource, 0);

        assertThat(resource.getJSON(), is(JSON_DATA));
        assertThat(resource.isValid(), is(true));
        assertUpdateInvoked(resource, 1);
    }

    /**
     * Test {@link AcmeJsonResource#setJSON(JSON)}.
     */
    @Test
    public void testSetJson() {
        Login login = TestUtils.login();

        JSON jsonData2 = getJSON("requestOrderResponse");

        AcmeJsonResource resource = new DummyJsonResource(login, LOCATION_URL);
        assertThat(resource.isValid(), is(false));
        assertUpdateInvoked(resource, 0);

        resource.setJSON(JSON_DATA);
        assertThat(resource.getJSON(), is(JSON_DATA));
        assertThat(resource.isValid(), is(true));
        assertUpdateInvoked(resource, 0);

        resource.setJSON(jsonData2);
        assertThat(resource.getJSON(), is(jsonData2));
        assertThat(resource.isValid(), is(true));
        assertUpdateInvoked(resource, 0);
    }

    /**
     * Test {@link AcmeJsonResource#invalidate()}.
     */
    @Test
    public void testInvalidate() {
        Login login = TestUtils.login();

        AcmeJsonResource resource = new DummyJsonResource(login, LOCATION_URL);
        assertThat(resource.isValid(), is(false));
        assertUpdateInvoked(resource, 0);

        resource.setJSON(JSON_DATA);
        assertThat(resource.isValid(), is(true));
        assertUpdateInvoked(resource, 0);

        resource.invalidate();
        assertThat(resource.isValid(), is(false));
        assertUpdateInvoked(resource, 0);

        assertThat(resource.getJSON(), is(JSON_DATA));
        assertThat(resource.isValid(), is(true));
        assertUpdateInvoked(resource, 1);
    }

    /**
     * Assert that {@link AcmeJsonResource#update()} has been invoked a given number of
     * times.
     *
     * @param resource
     *            {@link AcmeJsonResource} to test
     * @param count
     *            Expected number of times
     */
    private static void assertUpdateInvoked(AcmeJsonResource resource, int count) {
        DummyJsonResource dummy = (DummyJsonResource) resource;
        assertThat("update counter", dummy.updateCount, is(count));
    }

    /**
     * Minimum implementation of {@link AcmeJsonResource}.
     */
    private static class DummyJsonResource extends AcmeJsonResource {
        private static final long serialVersionUID = -6459238185161771948L;

        private int updateCount = 0;

        public DummyJsonResource(Login login, URL location) {
            super(login, location);
        }

        public DummyJsonResource(Login login, URL location, JSON json) {
            super(login, location);
            setJSON(json);
        }

        @Override
        public void update() throws AcmeException {
            // update() is tested individually in all AcmeJsonResource subclasses.
            // Here we just simulate the update, by setting a JSON.
            updateCount++;
            setJSON(JSON_DATA);
        }
    }

}
