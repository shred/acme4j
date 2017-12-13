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
package org.shredzone.acme4j.connector;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit test for {@link ResourceIterator}.
 */
public class ResourceIteratorTest {

    private final int PAGES = 4;
    private final int RESOURCES_PER_PAGE = 5;
    private final String TYPE = "authorizations";

    private List<URL> resourceURLs = new ArrayList<>(PAGES * RESOURCES_PER_PAGE);
    private List<URL> pageURLs = new ArrayList<>(PAGES);

    @Before
    public void setup() {
        resourceURLs.clear();
        for (int ix = 0; ix < RESOURCES_PER_PAGE * PAGES; ix++) {
            resourceURLs.add(url("https://example.com/acme/auth/" + ix));
        }

        pageURLs.clear();
        for (int ix = 0; ix < PAGES; ix++) {
            pageURLs.add(url("https://example.com/acme/batch/" + ix));
        }
    }

    /**
     * Test if the {@link ResourceIterator} handles a {@code null} start URL.
     */
    @Test(expected = NoSuchElementException.class)
    public void nullTest() throws IOException {
        Iterator<Authorization> it = createIterator(null);

        assertThat(it, not(nullValue()));
        assertThat(it.hasNext(), is(false));
        it.next(); // throws NoSuchElementException
    }

    /**
     * Test if the {@link ResourceIterator} returns all objects in the correct order.
     */
    @Test
    public void iteratorTest() throws IOException {
        List<URL> result = new ArrayList<>();

        Iterator<Authorization> it = createIterator(pageURLs.get(0));
        while (it.hasNext()) {
            result.add(it.next().getLocation());
        }

        assertThat(result, is(equalTo(resourceURLs)));
    }

    /**
     * Test unusual {@link Iterator#next()} and {@link Iterator#hasNext()} usage.
     */
    @Test
    public void nextHasNextTest() throws IOException {
        List<URL> result = new ArrayList<>();

        Iterator<Authorization> it = createIterator(pageURLs.get(0));
        assertThat(it.hasNext(), is(true));
        assertThat(it.hasNext(), is(true));

        // don't try this at home, kids...
        try {
            for (;;) {
                result.add(it.next().getLocation());
            }
        } catch (NoSuchElementException ex) {
            assertThat(it.hasNext(), is(false));
            assertThat(it.hasNext(), is(false));
        }

        assertThat(result, is(equalTo(resourceURLs)));
    }

    /**
     * Test that {@link Iterator#remove()} fails.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void removeTest() throws IOException {
        Iterator<Authorization> it = createIterator(pageURLs.get(0));
        it.next();
        it.remove(); // throws UnsupportedOperationException
    }

    /**
     * Creates a new {@link Iterator} of {@link Authorization} objects.
     *
     * @param first
     *            URL of the first page
     * @return Created {@link Iterator}
     */
    private Iterator<Authorization> createIterator(URL first) throws IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private int ix;

            @Override
            public void sendRequest(URL url, Session session) {
                ix = pageURLs.indexOf(url);
                assertThat(ix, is(greaterThanOrEqualTo(0)));
            }

            @Override
            public JSON readJsonResponse() {
                int start = ix * RESOURCES_PER_PAGE;
                int end = (ix + 1) * RESOURCES_PER_PAGE;

                JSONBuilder cb = new JSONBuilder();
                cb.array(TYPE, resourceURLs.subList(start, end).toArray());

                return JSON.parse(cb.toString());
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                if ("next".equals(relation) && (ix + 1 < pageURLs.size())) {
                    return Arrays.asList(pageURLs.get(ix + 1));
                }
                return Collections.emptyList();
            }
        };

        Session session = provider.createSession();

        provider.close();

        return new ResourceIterator<>(session, TYPE, first, Authorization::bind);
    }

}
