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

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.BiFunction;

import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Session;
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

    private final Session session;
    private final String field;
    private final Deque<URL> urlList = new ArrayDeque<>();
    private final BiFunction<Session, URL, T> creator;
    private boolean eol = false;
    private URL nextUrl;

    /**
     * Creates a new {@link ResourceIterator}.
     *
     * @param session
     *            {@link Session} to bind this iterator to
     * @param field
     *            Field name to be used in the JSON response
     * @param start
     *            URL of the first JSON array, may be {@code null} for an empty iterator
     * @param creator
     *            Creator for an {@link AcmeResource} that is bound to the given
     *            {@link Session} and {@link URL}.
     */
    public ResourceIterator(Session session, String field, URL start, BiFunction<Session, URL, T> creator) {
        this.session = Objects.requireNonNull(session, "session");
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

        URL next = urlList.poll();
        if (next == null) {
            eol = true;
            throw new NoSuchElementException("no more " + field);
        }

        return creator.apply(session, next);
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
        try (Connection conn = session.provider().connect()) {
            conn.sendRequest(nextUrl, session);
            conn.accept(HttpURLConnection.HTTP_OK);

            JSON json = conn.readJsonResponse();
            fillUrlList(json);

            nextUrl = conn.getLink("next");
        }
    }

    /**
     * Fills the url list with the URLs found in the desired field.
     *
     * @param json
     *            JSON map to read from
     */
    private void fillUrlList(JSON json) {
        JSON.Array array = json.get(field).asArray();
        if (array == null) {
            return;
        }

        array.stream().map(JSON.Value::asURL).forEach(urlList::add);
    }

}
