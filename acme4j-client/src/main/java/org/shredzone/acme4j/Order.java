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

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
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
    private List<String> identifiers;
    private Instant notBefore;
    private Instant notAfter;
    private Problem error;
    private List<URL> authorizations;
    private URL finalizeUrl;
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
     * Returns a {@link Problem} document if the order failed.
     */
    public Problem getError() {
        load();
        return error;
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Instant getExpires() {
        load();
        return expires;
    }

    /**
     * Gets the list of domain names to be ordered.
     */
    public List<String> getDomains() {
        return identifiers;
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
     * Gets the location {@link URL} of where to send the finalization call to.
     * <p>
     * For internal purposes. Use {@link #execute(byte[])} to finalize an order.
     */
    public URL getFinalizeLocation() {
        load();
        return finalizeUrl;
    }

    /**
     * Finalizes the order, by providing a CSR.
     * <p>
     * After a successful finalization, the certificate is available at
     * {@link #getCertificate()}.
     * <p>
     * Even though the ACME protocol uses the term "finalize an order", this method is
     * called {@link #execute(byte[])} to avoid confusion with the general
     * {@link Object#finalize()} method.
     *
     * @param csr
     *            CSR containing the parameters for the certificate being requested, in
     *            DER format
     */
    public void execute(byte[] csr) throws AcmeException {
        LOG.debug("finalize");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putBase64("csr", csr);

            conn.sendSignedRequest(getFinalizeLocation(), claims, getSession());
        }
        loaded = false; // invalidate this object
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
                throw new AcmeLazyLoadingException(this, ex);
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
        this.notBefore = json.get("notBefore").asInstant();
        this.notAfter = json.get("notAfter").asInstant();
        this.finalizeUrl = json.get("finalizeURL").asURL();

        URL certUrl = json.get("certificate").asURL();
        certificate = certUrl != null ? Certificate.bind(getSession(), certUrl) : null;

        this.error = json.get("error").asProblem(getLocation());

        this.identifiers = json.get("identifiers").asArray().stream()
                .map(JSON.Value::asObject)
                .map(it -> it.get("value").asString())
                .collect(toList());

        this.authorizations = json.get("authorizations").asArray().stream()
                .map(JSON.Value::asURL)
                .collect(toList());

        loaded = true;
    }

}
