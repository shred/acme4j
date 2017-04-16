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
import java.net.URI;
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
import org.shredzone.acme4j.util.JSON;

/**
 * An {@link Iterator} that fetches a batch of URIs from the ACME server, and generates
 * {@link AcmeResource} instances.
 *
 * @param <T>
 *            {@link AcmeResource} type to iterate over
 */
public class ResourceIterator<T extends AcmeResource> implements Iterator<T> {

    private final Session session;
    private final String field;
    private final Deque<URI> uriList = new ArrayDeque<>();
    private final BiFunction<Session, URI, T> creator;
    private boolean eol = false;
    private URI nextUri;

    /**
     * Creates a new {@link ResourceIterator}.
     *
     * @param session
     *            {@link Session} to bind this iterator to
     * @param field
     *            Field name to be used in the JSON response
     * @param start
     *            URI of the first JSON array, may be {@code null} for an empty iterator
     * @param creator
     *            Creator for an {@link AcmeResource} that is bound to the given
     *            {@link Session} and {@link URI}.
     */
    public ResourceIterator(Session session, String field, URI start, BiFunction<Session, URI, T> creator) {
        this.session = Objects.requireNonNull(session, "session");
        this.field = Objects.requireNonNull(field, "field");
        this.nextUri = start;
        this.creator = Objects.requireNonNull(creator, "creator");
    }

    /**
     * Checks if there is another object in the result.
     *
     * @throws AcmeProtocolException
     *             if the next batch of URIs could not be fetched from the server
     */
    @Override
    public boolean hasNext() {
        if (eol) {
            return false;
        }

        if (uriList.isEmpty()) {
            fetch();
        }

        if (uriList.isEmpty()) {
            eol = true;
        }

        return !uriList.isEmpty();
    }

    /**
     * Returns the next object of the result.
     *
     * @throws AcmeProtocolException
     *             if the next batch of URIs could not be fetched from the server
     * @throws NoSuchElementException
     *             if there are no more entries
     */
    @Override
    public T next() {
        if (!eol && uriList.isEmpty()) {
            fetch();
        }

        URI next = uriList.poll();
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
     * Fetches the next batch of URIs. Handles exceptions. Does nothing if there is no
     * URI of the next batch.
     */
    private void fetch() {
        if (nextUri == null) {
            return;
        }

        try {
            readAndQueue();
        } catch (AcmeException ex) {
            throw new AcmeProtocolException("failed to read next set of " + field, ex);
        }
    }

    /**
     * Reads the next batch of URIs from the server, and fills the queue with the URIs. If
     * there is a "next" header, it is used for the next batch of URIs.
     */
    private void readAndQueue() throws AcmeException {
        try (Connection conn = session.provider().connect()) {
            conn.sendRequest(nextUri, session);
            conn.accept(HttpURLConnection.HTTP_OK);

            JSON json = conn.readJsonResponse();
            fillUriList(json);

            nextUri = conn.getLink("next");
        }
    }

    /**
     * Fills the uri list with the URIs found in the desired field.
     *
     * @param json
     *            JSON map to read from
     */
    private void fillUriList(JSON json) {
        json.get(field).asArray().stream()
                .map(JSON.Value::asURI)
                .forEach(uriList::add);
    }

}
