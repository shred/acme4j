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

import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.util.CSRBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A representation of a certificate order at the CA.
 */
public class Order extends AcmeJsonResource implements PollableResource {
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
    @Override
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
                    .collect(toList());
        }
        return unmodifiableList(authorizations);
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
    @SuppressFBWarnings("EI_EXPOSE_REP")    // behavior is intended
    public Certificate getCertificate() {
        if (certificate == null) {
            certificate = getJSON().get("star-certificate")
                    .optional()
                    .or(() -> getJSON().get("certificate").optional())
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
     * @deprecated Use {@link #getCertificate()} for STAR certificates as well.
     */
    @Deprecated
    @SuppressFBWarnings("EI_EXPOSE_REP")    // behavior is intended
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
     * Returns whether this is a STAR certificate ({@code true}) or a standard certificate
     * ({@code false}).
     *
     * @since 3.5.0
     */
    public boolean isAutoRenewalCertificate() {
        return getJSON().contains("star-certificate");
    }

    /**
     * Finalizes the order.
     * <p>
     * If the finalization was successful, the certificate is provided via
     * {@link #getCertificate()}.
     * <p>
     * Even though the ACME protocol uses the term "finalize an order", this method is
     * called {@link #execute(KeyPair)} to avoid confusion with the problematic
     * {@link Object#finalize()} method.
     *
     * @param domainKeyPair
     *         The {@link KeyPair} that is going to be certified. This is <em>not</em>
     *         your account's keypair!
     * @see #execute(KeyPair, Consumer)
     * @see #execute(PKCS10CertificationRequest)
     * @see #execute(byte[])
     * @see #waitUntilReady(Duration)
     * @see #waitForCompletion(Duration)
     * @since 3.0.0
     */
    public void execute(KeyPair domainKeyPair) throws AcmeException {
        execute(domainKeyPair, csrBuilder -> {});
    }

    /**
     * Finalizes the order (see {@link #execute(KeyPair)}).
     * <p>
     * This method also accepts a builderConsumer that can be used to add further details
     * to the CSR (e.g. your organization). The identifiers (IPs, domain names, etc.) are
     * automatically added to the CSR.
     *
     * @param domainKeyPair
     *         The {@link KeyPair} that is going to be used together with the certificate.
     *         This is not your account's keypair!
     * @param builderConsumer
     *         {@link Consumer} that adds further details to the provided
     *         {@link CSRBuilder}.
     * @see #execute(KeyPair)
     * @see #execute(PKCS10CertificationRequest)
     * @see #execute(byte[])
     * @see #waitUntilReady(Duration)
     * @see #waitForCompletion(Duration)
     * @since 3.0.0
     */
    public void execute(KeyPair domainKeyPair, Consumer<CSRBuilder> builderConsumer) throws AcmeException {
        try {
            var csrBuilder = new CSRBuilder();
            csrBuilder.addIdentifiers(getIdentifiers());
            builderConsumer.accept(csrBuilder);
            csrBuilder.sign(domainKeyPair);
            execute(csrBuilder.getCSR());
        } catch (IOException ex) {
            throw new AcmeException("Failed to create CSR", ex);
        }
    }

    /**
     * Finalizes the order (see {@link #execute(KeyPair)}).
     * <p>
     * This method receives a {@link PKCS10CertificationRequest} instance of a CSR that
     * was generated externally. Use this method to gain full control over the content of
     * the CSR. The CSR is not checked by acme4j, but just transported to the CA. It is
     * your responsibility that it matches to the order.
     *
     * @param csr
     *         {@link PKCS10CertificationRequest} to be used for this order.
     * @see #execute(KeyPair)
     * @see #execute(KeyPair, Consumer)
     * @see #execute(byte[])
     * @see #waitUntilReady(Duration)
     * @see #waitForCompletion(Duration)
     * @since 3.0.0
     */
    public void execute(PKCS10CertificationRequest csr) throws AcmeException {
        try {
            execute(csr.getEncoded());
        } catch (IOException ex) {
            throw new AcmeException("Invalid CSR", ex);
        }
    }

    /**
     * Finalizes the order (see {@link #execute(KeyPair)}).
     * <p>
     * This method receives a byte array containing an encoded CSR that was generated
     * externally. Use this method to gain full control over the content of the CSR. The
     * CSR is not checked by acme4j, but just transported to the CA. It is your
     * responsibility that it matches to the order.
     *
     * @param csr
     *         Binary representation of a CSR containing the parameters for the
     *         certificate being requested, in DER format
     * @see #waitUntilReady(Duration)
     * @see #waitForCompletion(Duration)
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
     * Waits until the order is ready for finalization.
     * <p>
     * Is is ready if it reaches {@link Status#READY}. The method will also return if the
     * order already has another terminal state, which is either {@link Status#VALID} or
     * {@link Status#INVALID}.
     * <p>
     * This method is synchronous and blocks the current thread.
     *
     * @param timeout
     *         Timeout until a terminal status must have been reached
     * @return Status that was reached
     * @since 3.4.0
     */
    public Status waitUntilReady(Duration timeout)
            throws AcmeException, InterruptedException {
        return waitForStatus(EnumSet.of(Status.READY, Status.VALID, Status.INVALID), timeout);
    }

    /**
     * Waits until the order finalization is completed.
     * <p>
     * Is is completed if it reaches either {@link Status#VALID} or
     * {@link Status#INVALID}.
     * <p>
     * This method is synchronous and blocks the current thread.
     *
     * @param timeout
     *         Timeout until a terminal status must have been reached
     * @return Status that was reached
     * @since 3.4.0
     */
    public Status waitForCompletion(Duration timeout)
            throws AcmeException, InterruptedException {
        return waitForStatus(EnumSet.of(Status.VALID, Status.INVALID), timeout);
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

    /**
     * Returns the selected profile.
     *
     * @since 3.5.0
     * @throws AcmeNotSupportedException if profile is not supported
     */
    public String getProfile() {
        return getJSON().getFeature("profile").asString();
    }

    @Override
    protected void invalidate() {
        super.invalidate();
        certificate = null;
        autoRenewalCertificate = null;
        authorizations = null;
    }
}
