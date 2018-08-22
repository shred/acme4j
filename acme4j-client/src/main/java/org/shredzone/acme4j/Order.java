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
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a certificate order.
 */
@ParametersAreNonnullByDefault
public class Order extends AcmeJsonResource {
    private static final long serialVersionUID = 5435808648658292177L;
    private static final Logger LOG = LoggerFactory.getLogger(Order.class);

    protected Order(Login login, URL location) {
        super(login, location);
    }

    /**
     * Returns the current status of the order.
     * <p>
     * Possible values are: {@link Status#PENDING}, {@link Status#READY},
     * {@link Status#PROCESSING}, {@link Status#VALID}, {@link Status#INVALID}.
     */
    public Status getStatus() {
        return getJSON().get("status").asStatus();
    }

    /**
     * Returns a {@link Problem} document if the order failed.
     */
    @CheckForNull
    public Problem getError() {
        return getJSON().get("error").map(v -> v.asProblem(getLocation())).orElse(null);
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    @CheckForNull
    public Instant getExpires() {
        return getJSON().get("expires").map(Value::asInstant).orElse(null);
    }

    /**
     * Gets the list of domain names to be ordered.
     *
     * @deprecated Use {@link #getIdentifiers()}. This method only returns DNS type
     *             identifiers for compatibility reasons.
     */
    @Deprecated
    public List<String> getDomains() {
        return getIdentifiers().stream()
                    .filter(i -> Identifier.TYPE_DNS.equals(i.getType()))
                    .map(Identifier::getDomain)
                    .collect(toList());
    }

    /**
     * Gets the list of {@link Identifier} to be ordered.
     *
     * @since 2.3
     */
    public List<Identifier> getIdentifiers() {
        return Collections.unmodifiableList(getJSON().get("identifiers")
                    .asArray()
                    .stream()
                    .map(Value::asIdentifier)
                    .collect(toList()));
    }

    /**
     * Gets the "not before" date that was used for the order, or {@code null}.
     */
    @CheckForNull
    public Instant getNotBefore() {
        return getJSON().get("notBefore").map(Value::asInstant).orElse(null);
    }

    /**
     * Gets the "not after" date that was used for the order, or {@code null}.
     */
    @CheckForNull
    public Instant getNotAfter() {
        return getJSON().get("notAfter").map(Value::asInstant).orElse(null);
    }

    /**
     * Gets the {@link Authorization} required for this order, in no specific order.
     */
    public List<Authorization> getAuthorizations() {
        Login login = getLogin();
        return Collections.unmodifiableList(getJSON().get("authorizations")
                    .asArray()
                    .stream()
                    .map(Value::asURL)
                    .map(login::bindAuthorization)
                    .collect(toList()));
    }

    /**
     * Gets the location {@link URL} of where to send the finalization call to.
     * <p>
     * For internal purposes. Use {@link #execute(byte[])} to finalize an order.
     */
    public URL getFinalizeLocation() {
        return getJSON().get("finalize").asURL();
    }

    /**
     * Gets the {@link Certificate} if it is available. {@code null} otherwise.
     */
    @CheckForNull
    public Certificate getCertificate() {
        return getJSON().get("certificate")
                    .map(Value::asURL)
                    .map(getLogin()::bindCertificate)
                    .orElse(null);
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
        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putBase64("csr", csr);

            conn.sendSignedRequest(getFinalizeLocation(), claims, getLogin());
        }
        invalidate();
    }

    /**
     * Checks if this order is recurrent, according to the ACME STAR specifications.
     *
     * @since 2.3
     */
    public boolean isRecurrent() {
        return getJSON().get("recurrent")
                    .optional()
                    .map(Value::asBoolean)
                    .orElse(false);
    }

    /**
     * Returns the earliest date of validity of the first certificate issued, or
     * {@code null}.
     *
     * @since 2.3
     */
    @CheckForNull
    public Instant getRecurrentStart() {
        return getJSON().get("recurrent-start-date")
                    .optional()
                    .map(Value::asInstant)
                    .orElse(null);
    }

    /**
     * Returns the latest date of validity of the last certificate issued, or
     * {@code null}.
     *
     * @since 2.3
     */
    @CheckForNull
    public Instant getRecurrentEnd() {
        return getJSON().get("recurrent-end-date")
                    .optional()
                    .map(Value::asInstant)
                    .orElse(null);
    }

    /**
     * Returns the maximum validity period of each certificate, or {@code null}.
     *
     * @since 2.3
     */
    @CheckForNull
    public Duration getRecurrentCertificateValidity() {
        return getJSON().get("recurrent-certificate-validity")
                    .optional()
                    .map(Value::asDuration)
                    .orElse(null);
    }

    /**
     * Cancels a recurrent order.
     *
     * @since 2.3
     */
    public void cancelRecurrent() throws AcmeException {
        if (!getSession().getMetadata().isStarEnabled()) {
            throw new AcmeException("CA does not support short-term automatic renewals");
        }

        LOG.debug("cancel");
        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.put("status", "canceled");

            conn.sendSignedRequest(getLocation(), claims, getLogin());

            JSON json = conn.readJsonResponse();
            if (json != null) {
                setJSON(json);
            }
        }
    }

}
