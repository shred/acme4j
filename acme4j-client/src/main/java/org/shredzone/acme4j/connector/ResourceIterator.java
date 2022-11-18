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

import java.net.URL;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.BiFunction;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * An {@link Iterator} that fetches a batch of URLs from the ACME server, and generates
 * {@link AcmeResource} instances.
 *
 * @param <T>
 *            {@link AcmeResource} type to iterate over
 */
public class ResourceIterator<T extends AcmeResource> implements Iterator<T> {

    private final Login login;
    private final String field;
    private final Deque<URL> urlList = new ArrayDeque<>();
    private final BiFunction<Login, URL, T> creator;
    private boolean eol = false;
    private @Nullable URL nextUrl;

    /**
     * Creates a new {@link ResourceIterator}.
     *
     * @param login
     *            {@link Login} to bind this iterator to
     * @param field
     *            Field name to be used in the JSON response
     * @param start
     *            URL of the first JSON array, may be {@code null} for an empty iterator
     * @param creator
     *            Creator for an {@link AcmeResource} that is bound to the given
     *            {@link Login} and {@link URL}.
     */
    public ResourceIterator(Login login, String field, @Nullable URL start, BiFunction<Login, URL, T> creator) {
        this.login = Objects.requireNonNull(login, "login");
        this.field = Objects.requireNonNull(field, "field");
        this.nextUrl = start;
        this.creator = Objects.requireNonNull(creator, "creator");
    }

    /**
     * Checks if there is another object in the result.
     *
     * @throws AcmeProtocolException
     *             if the next batch of URLs could not be fetched from the server
     */
    @Override
    public boolean hasNext() {
        if (eol) {
            return false;
        }

        if (urlList.isEmpty()) {
            fetch();
        }

        if (urlList.isEmpty()) {
            eol = true;
        }

        return !urlList.isEmpty();
    }

    /**
     * Returns the next object of the result.
     *
     * @throws AcmeProtocolException
     *             if the next batch of URLs could not be fetched from the server
     * @throws NoSuchElementException
     *             if there are no more entries
     */
    @Override
    public T next() {
        if (!eol && urlList.isEmpty()) {
            fetch();
        }

        var next = urlList.poll();
        if (next == null) {
            eol = true;
            throw new NoSuchElementException("no more " + field);
        }

        return creator.apply(login, next);
    }

    /**
     * Unsupported operation, only here to satisfy the {@link Iterator} interface.
     */
    @Override
    public void remove() {
        throw new UnsupportedOperationException("cannot remove " + field);
    }

    /**
     * Fetches the next batch of URLs. Handles exceptions. Does nothing if there is no
     * URL of the next batch.
     */
    private void fetch() {
        if (nextUrl == null) {
            return;
        }

        try {
            readAndQueue();
        } catch (AcmeException ex) {
            throw new AcmeProtocolException("failed to read next set of " + field, ex);
        }
    }

    /**
     * Reads the next batch of URLs from the server, and fills the queue with the URLs. If
     * there is a "next" header, it is used for the next batch of URLs.
     */
    private void readAndQueue() throws AcmeException {
        var session = login.getSession();
        try (var conn = session.connect()) {
            conn.sendSignedPostAsGetRequest(nextUrl, login);
            fillUrlList(conn.readJsonResponse());

            nextUrl = conn.getLinks("next").stream().findFirst().orElse(null);
        }
    }

    /**
     * Fills the url list with the URLs found in the desired field.
     *
     * @param json
     *            JSON map to read from
     */
    private void fillUrlList(JSON json) {
        json.get(field).asArray().stream()
                .map(JSON.Value::asURL)
                .forEach(urlList::add);
    }

}
