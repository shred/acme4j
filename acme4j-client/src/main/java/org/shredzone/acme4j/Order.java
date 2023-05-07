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

import static java.util.stream.Collectors.toUnmodifiableList;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A representation of a certificate order at the CA.
 */
public class Order extends AcmeJsonResource {
    private static final long serialVersionUID = 5435808648658292177L;
    private static final Logger LOG = LoggerFactory.getLogger(Order.class);

    private transient @Nullable Certificate certificate = null;
    private transient @Nullable Certificate autoRenewalCertificate = null;
    private transient @Nullable List<Authorization> authorizations = null;

    protected Order(Login login, URL location) {
        super(login, location);
    }

    /**
     * Returns the current status of the order.
     * <p>
     * Possible values are: {@link Status#PENDING}, {@link Status#READY},
     * {@link Status#PROCESSING}, {@link Status#VALID}, {@link Status#INVALID}.
     * If the server supports STAR, another possible value is {@link Status#CANCELED}.
     */
    public Status getStatus() {
        return getJSON().get("status").asStatus();
    }

    /**
     * Returns a {@link Problem} document with the reason if the order has failed.
     */
    public Optional<Problem> getError() {
        return getJSON().get("error").map(v -> v.asProblem(getLocation()));
    }

    /**
     * Gets the expiry date of the authorization, if set by the server.
     */
    public Optional<Instant> getExpires() {
        return getJSON().get("expires").map(Value::asInstant);
    }

    /**
     * Gets a list of {@link Identifier} that are connected to this order.
     *
     * @since 2.3
     */
    public List<Identifier> getIdentifiers() {
        return getJSON().get("identifiers")
                    .asArray()
                    .stream()
                    .map(Value::asIdentifier)
                    .collect(toUnmodifiableList());
    }

    /**
     * Gets the "not before" date that was used for the order.
     */
    public Optional<Instant> getNotBefore() {
        return getJSON().get("notBefore").map(Value::asInstant);
    }

    /**
     * Gets the "not after" date that was used for the order.
     */
    public Optional<Instant> getNotAfter() {
        return getJSON().get("notAfter").map(Value::asInstant);
    }

    /**
     * Gets the {@link Authorization} that are required to fulfil this order, in no
     * specific order.
     */
    public List<Authorization> getAuthorizations() {
        if (authorizations == null) {
            var login = getLogin();
            authorizations = getJSON().get("authorizations")
                    .asArray()
                    .stream()
                    .map(Value::asURL)
                    .map(login::bindAuthorization)
                    .collect(toUnmodifiableList());
        }
        return authorizations;
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
     * Gets the {@link Certificate}.
     *
     * @throws IllegalStateException
     *         if the order is not ready yet. You must finalize the order first, and wait
     *         for the status to become {@link Status#VALID}.
     */
    public Certificate getCertificate() {
        if (certificate == null) {
            certificate = getJSON().get("certificate")
                    .map(Value::asURL)
                    .map(getLogin()::bindCertificate)
                    .orElseThrow(() -> new IllegalStateException("Order is not completed"));
        }
        return certificate;
    }

    /**
     * Gets the STAR extension's {@link Certificate} if it is available.
     *
     * @since 2.6
     * @throws IllegalStateException
     *         if the order is not ready yet. You must finalize the order first, and wait
     *         for the status to become {@link Status#VALID}. It is also thrown if the
     *         order has been {@link Status#CANCELED}.
     */
    public Certificate getAutoRenewalCertificate() {
        if (autoRenewalCertificate == null) {
            autoRenewalCertificate = getJSON().get("star-certificate")
                    .optional()
                    .map(Value::asURL)
                    .map(getLogin()::bindCertificate)
                    .orElseThrow(() -> new IllegalStateException("Order is in an invalid state"));
        }
        return autoRenewalCertificate;
    }

    /**
     * Finalizes the order, by providing a CSR.
     * <p>
     * After a successful finalization, the certificate is available at
     * {@link #getCertificate()}.
     * <p>
     * Even though the ACME protocol uses the term "finalize an order", this method is
     * called {@link #execute(byte[])} to avoid confusion with the problematic
     * {@link Object#finalize()} method.
     *
     * @param csr
     *         CSR containing the parameters for the certificate being requested, in DER
     *         format
     */
    public void execute(byte[] csr) throws AcmeException {
        LOG.debug("finalize");
        try (var conn = getSession().connect()) {
            var claims = new JSONBuilder();
            claims.putBase64("csr", csr);

            conn.sendSignedRequest(getFinalizeLocation(), claims, getLogin());
        }
        invalidate();
    }

    /**
     * Checks if this order is auto-renewing, according to the ACME STAR specifications.
     *
     * @since 2.3
     */
    public boolean isAutoRenewing() {
        return getJSON().get("auto-renewal")
                    .optional()
                    .isPresent();
    }

    /**
     * Returns the earliest date of validity of the first certificate issued.
     *
     * @since 2.3
     * @throws AcmeNotSupportedException if auto-renewal is not supported
     */
    public Optional<Instant> getAutoRenewalStartDate() {
        return getJSON().getFeature("auto-renewal")
                    .map(Value::asObject)
                    .orElseGet(JSON::empty)
                    .get("start-date")
                    .optional()
                    .map(Value::asInstant);
    }

    /**
     * Returns the latest date of validity of the last certificate issued.
     *
     * @since 2.3
     * @throws AcmeNotSupportedException if auto-renewal is not supported
     */
    public Instant getAutoRenewalEndDate() {
        return getJSON().getFeature("auto-renewal")
                    .map(Value::asObject)
                    .orElseGet(JSON::empty)
                    .get("end-date")
                    .asInstant();
    }

    /**
     * Returns the maximum lifetime of each certificate.
     *
     * @since 2.3
     * @throws AcmeNotSupportedException if auto-renewal is not supported
     */
    public Duration getAutoRenewalLifetime() {
        return getJSON().getFeature("auto-renewal")
                    .optional()
                    .map(Value::asObject)
                    .orElseGet(JSON::empty)
                    .get("lifetime")
                    .asDuration();
    }

    /**
     * Returns the pre-date period of each certificate.
     *
     * @since 2.7
     * @throws AcmeNotSupportedException if auto-renewal is not supported
     */
    public Optional<Duration> getAutoRenewalLifetimeAdjust() {
        return getJSON().getFeature("auto-renewal")
                    .optional()
                    .map(Value::asObject)
                    .orElseGet(JSON::empty)
                    .get("lifetime-adjust")
                    .optional()
                    .map(Value::asDuration);
    }

    /**
     * Returns {@code true} if STAR certificates from this order can also be fetched via
     * GET requests.
     *
     * @since 2.6
     */
    public boolean isAutoRenewalGetEnabled() {
        return getJSON().getFeature("auto-renewal")
                    .optional()
                    .map(Value::asObject)
                    .orElseGet(JSON::empty)
                    .get("allow-certificate-get")
                    .optional()
                    .map(Value::asBoolean)
                    .orElse(false);
    }

    /**
     * Cancels an auto-renewing order.
     *
     * @since 2.3
     */
    public void cancelAutoRenewal() throws AcmeException {
        if (!getSession().getMetadata().isAutoRenewalEnabled()) {
            throw new AcmeNotSupportedException("auto-renewal");
        }

        LOG.debug("cancel");
        try (var conn = getSession().connect()) {
            var claims = new JSONBuilder();
            claims.put("status", "canceled");

            conn.sendSignedRequest(getLocation(), claims, getLogin());
            setJSON(conn.readJsonResponse());
        }
    }

    @Override
    protected void invalidate() {
        super.invalidate();
        certificate = null;
        autoRenewalCertificate = null;
        authorizations = null;
    }
}
