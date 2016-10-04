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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * An {@link Iterator} that fetches a batch of URIs from the ACME server, and
 * generates {@link AcmeResource} instances.
 */
public abstract class ResourceIterator<T extends AcmeResource> implements Iterator<T> {

    private final Session session;
    private final String field;
    private final Deque<URI> uriList = new ArrayDeque<>();
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
     */
    public ResourceIterator(Session session, String field, URI start) {
        this.session = session;
        this.field = field;
        this.nextUri = start;
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

        return create(session, next);
    }

    /**
     * Unsupported operation, only here to satisfy the {@link Iterator} interface.
     */
    @Override
    public void remove() {
        throw new UnsupportedOperationException("cannot remove " + field);
    }

    /**
     * Creates a new {@link AcmeResource} object by binding it to the {@link Session} and
     * using the given {@link URI}.
     *
     * @param session
     *            {@link Session} to bind the object to
     * @param uri
     *            {@link URI} of the resource
     * @return Created object
     */
    protected abstract T create(Session session, URI uri);

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
    @SuppressWarnings("unchecked")
    private void readAndQueue() throws AcmeException {
        try (Connection conn = session.provider().connect()) {
            int rc = conn.sendRequest(nextUri, session);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }

            Map<String, Object> json = conn.readJsonResponse();
            try {
                Collection<String> array = (Collection<String>) json.get(field);
                if (array != null) {
                    for (String uri : array) {
                        uriList.add(new URI(uri));
                    }
                }
            } catch (ClassCastException ex) {
                throw new AcmeProtocolException("Expected an array");
            } catch (URISyntaxException ex) {
                throw new AcmeProtocolException("Invalid URI", ex);
            }

            nextUri = conn.getLink("next");
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

}
