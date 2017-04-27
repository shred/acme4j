/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
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

import static java.util.stream.Collectors.toList;

import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate order.
 */
public class Order extends AcmeResource {
    private static final long serialVersionUID = 5435808648658292177L;
    private static final Logger LOG = LoggerFactory.getLogger(Order.class);

    private Status status;
    private Instant expires;
    private byte[] csr;
    private Instant notBefore;
    private Instant notAfter;
    private List<URL> authorizations;
    private Certificate certificate;
    private boolean loaded = false;

    protected Order(Session session, URL location) {
        super(session);
        setLocation(location);
    }

    /**
     * Creates a new instance of {@link Order} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location URL of the order
     * @return {@link Order} bound to the session and location
     */
    public static Order bind(Session session, URL location) {
        return new Order(session, location);
    }

    /**
     * Returns the current status of the order.
     */
    public Status getStatus() {
        load();
        return status;
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Instant getExpires() {
        load();
        return expires;
    }

    /**
     * Gets the CSR that was used for the order.
     */
    public byte[] getCsr() {
        load();
        return csr;
    }

    /**
     * Gets the "not before" date that was used for the order, or {@code null}.
     */
    public Instant getNotBefore() {
        load();
        return notBefore;
    }

    /**
     * Gets the "not after" date that was used for the order, or {@code null}.
     */
    public Instant getNotAfter() {
        load();
        return notAfter;
    }

    /**
     * Gets the {@link Authorization} required for this order.
     */
    public List<Authorization> getAuthorizations() {
        load();
        Session session = getSession();
        return authorizations.stream()
                .map(loc -> Authorization.bind(session, loc))
                .collect(toList());
    }

    /**
     * Gets the {@link Certificate} if it is available. {@code null} otherwise.
     */
    public Certificate getCertificate() {
        load();
        return certificate;
    }

    /**
     * Updates the order to the current account status.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            conn.sendRequest(getLocation(), getSession());
            conn.accept(HttpURLConnection.HTTP_OK);

            JSON json = conn.readJsonResponse();
            unmarshal(json);
         }
    }

    /**
     * Lazily updates the object's state when one of the getters is invoked.
     */
    protected void load() {
        if (!loaded) {
            try {
                update();
            } catch (AcmeException ex) {
                throw new AcmeProtocolException("Could not load lazily", ex);
            }
        }
    }

    /**
     * Sets order properties according to the given JSON data.
     *
     * @param json
     *            JSON data
     */
    public void unmarshal(JSON json) {
        this.status = json.get("status").asStatusOrElse(Status.UNKNOWN);
        this.expires = json.get("expires").asInstant();
        this.csr = json.get("csr").asBinary();
        this.notBefore = json.get("notBefore").asInstant();
        this.notAfter = json.get("notAfter").asInstant();

        URL certUrl = json.get("certificate").asURL();
        certificate = certUrl != null ? Certificate.bind(getSession(), certUrl) : null;

        this.authorizations = json.get("authorizations").asArray().stream()
                .map(JSON.Value::asURL)
                .collect(toList());

        loaded = true;
    }

}
