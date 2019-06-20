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

import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Unit tests for {@link MockResource}.
 */
public class MockResourceTest {

    @Test
    public void testGetters() throws Exception {
        final URL location = new URL("https://example.com/acme/example");
        final JSON json = JSON.empty();

        MockResource mockResource = new MockResource() {
            @Override
            public URL getLocation() {
                return location;
            }

            @Override
            public JSON toJSON() {
                return json;
            }
        };

        assertThat(mockResource.getUniqueId(), not(emptyOrNullString()));
        assertThat(mockResource.toString(), is("https://example.com/acme/example: {}"));
    }

    @Test
    public void testBuildUrl() {
        URL url = MockResource.buildUrl("foo", "abc", "123");
        assertThat(url.toString(), is("https://acme.test/foo/abc/123"));
    }

}
