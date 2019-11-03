/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.model;

import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.mock.connection.MockCertificateAuthority;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.CertificateController;
import org.shredzone.acme4j.mock.controller.FinalizeController;
import org.shredzone.acme4j.mock.controller.OrderController;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.util.CSRBuilder;

/**
 * A mock order.
 * <p>
 * It reflects the server side of {@link org.shredzone.acme4j.Order} objects.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockOrder extends MockResource {
    private final List<MockAuthorization> authorizations;
    private final List<Identifier> identifiers;
    private final MockCertificateAuthority mockCa;

    private Status status;
    private Instant expires;
    private Instant notBefore;
    private Instant notAfter;
    private Problem error;
    private byte[] encodedCsr;
    private List<X509Certificate> certificate;

    /**
     * Internal constructor. Use {@link MockOrder#create(Repository, Collection,
     * Collection, MockCertificateAuthority)}.
     */
    private MockOrder(Collection<Identifier> identifiers, Collection<MockAuthorization> authorizations,
              MockCertificateAuthority mockCa) {
        this.identifiers = unmodifiableList(new ArrayList<>(identifiers));
        this.authorizations = new ArrayList<>(authorizations);
        this.mockCa = mockCa;
    }

    /**
     * Creates a new {@link MockOrder} instance.
     *
     * @param repository
     *         {@link Repository} to add the resource to
     * @param identifiers
     *         A {@link Collection} of {@link Identifier} being ordered
     * @param authorizations
     *         A {@link Collection} of {@link MockAuthorization} required for this order
     * @param mockCa
     *          {@link MockCertificateAuthority} to be used for certificate signing
     * @return The generated {@link MockOrder}
     */
    public static MockOrder create(Repository repository, Collection<Identifier> identifiers,
               Collection<MockAuthorization> authorizations, MockCertificateAuthority mockCa) {
        MockOrder order = new MockOrder(identifiers, authorizations, mockCa);
        repository.addResource(order, OrderController::new);
        repository.addController(order.getFinalizeLocation(), new FinalizeController(order));
        repository.addController(order.getCertificateLocation(), new CertificateController(order));
        return order;
    }

    /**
     * Sets a generated CSR that matches the current state of the order.
     *
     * @param keyPair
     *         {@link KeyPair} to be used for signing the CSR
     */
    public void generateCsr(KeyPair keyPair) {
        try {
            CSRBuilder csrBuilder = new CSRBuilder();
            csrBuilder.addIdentifiers(getIdentifiers());
            csrBuilder.sign(keyPair);
            setCertificateSigningRequest(csrBuilder.getEncoded());
        } catch (IOException ex) {
            throw new IllegalStateException("Could not generate a CSR", ex);
        }
    }

    /**
     * Issues the signed certificate. The current CSR is read, signed by the {@link
     * org.shredzone.acme4j.mock.MockAcmeServer}'s CA, and then set as certificate chain.
     */
    public void issueCertificate() {
        if (encodedCsr == null) {
            throw new IllegalStateException("Set a CSR first");
        }
        setCertificate(mockCa.chain(mockCa.signCertificate(encodedCsr, notBefore, notAfter)));
    }

    /**
     * Returns the current order status.
     * <p>
     * If no concrete status was set via {@link #setStatus(Status)}, the mock resource
     * tries to deduce a reasonable status from its current state.
     */
    public Status getStatus() {
        if (status != null) {
            return status;
        }

        if (getError() != null) {
            return Status.INVALID;
        }

        if (certificate != null) {
            return Status.VALID;
        }

        if (encodedCsr != null) {
            return Status.PROCESSING;
        }

        if (authorizations.stream().map(MockAuthorization::getStatus).anyMatch(s -> s == Status.INVALID)) {
            return Status.INVALID;
        }

        if (authorizations.stream().map(MockAuthorization::getStatus).allMatch(s -> s == Status.VALID)) {
            return Status.READY;
        }

        return Status.PENDING;
    }

    /**
     * Sets the current order status.
     *
     * @param status
     *         new {@link Status}, or {@code null} to clear the status and let the
     *         resource decide on its current status automatically.
     */
    public void setStatus(@Nullable Status status) {
        this.status = status;
    }

    /**
     * Returns the expiration date of this order, or {@code null} if undefined.
     */
    @CheckForNull
    public Instant getExpires() {
        return expires;
    }

    /**
     * Sets the expiration date of this order.
     *
     * @param expires
     *         Expiration date, or {@code null} if undefined.
     */
    public void setExpires(@Nullable Instant expires) {
        this.expires = expires;
    }

    /**
     * Returns the requested "not-before" date of the certificate. {@code null} if no
     * such date was set.
     */
    @CheckForNull
    public Instant getNotBefore() {
        return notBefore;
    }

    /**
     * Sets the requested "not-before" date of the certificate.
     *
     * @param notBefore
     *         "not-before" date, or {@code null} if undefined.
     */
    public void setNotBefore(@Nullable Instant notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * Returns the requested "not-after" date of the certificate. {@code null} if no
     * such date was set.
     */
    @CheckForNull
    public Instant getNotAfter() {
        return notAfter;
    }

    /**
     * Sets the requested "not-after" date of the certificate.
     *
     * @param notAfter
     *         "not-after" date, or {@code null} if undefined.
     */
    public void setNotAfter(@Nullable Instant notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * Returns the {@link Problem} that has caused this order to fail. {@code null} if
     * there was no error.
     */
    @CheckForNull
    public Problem getError() {
        return error;
    }

    /**
     * Sets the {@link Problem} that has caused this order to fail.
     *
     * @param error
     *         {@link Problem} that caused the failure, or {@code null} if there was no
     *         error.
     */
    public void setError(@Nullable Problem error) {
        this.error = error;
    }

    /**
     * Returns the encoded PKCS#10 certification request from order finalization.
     */
    @CheckForNull
    public byte[] getCertificateSigningRequest() {
        return encodedCsr != null ? encodedCsr.clone() : null;
    }

    /**
     * Sets the CSR from order finalization.
     *
     * @param csr
     *         encoded PKCS#10 certification request, or {@code null} if the order has not
     *         been finalized yet
     */
    public void setCertificateSigningRequest(@Nullable byte[] csr) {
        encodedCsr = csr != null ? csr.clone() : null;
    }

    /**
     * Returns the certificate chain, or {@code null} if the order has not been finalized
     * yet.
     */
    @CheckForNull
    public List<X509Certificate> getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate chain after this order has been finalized.
     *
     * @param certificate
     *         {@link List} of {@link X509Certificate}, with the end entity certificate
     *         being the first entry, and each parent certificate in the next entries.
     *         {@code null} if the order is not finalized.
     */
    public void setCertificate(@Nullable List<X509Certificate> certificate) {
        this.certificate = certificate;
    }

    /**
     * Returns a {@link List} of all {@link MockAuthorization} that need to be processed
     * before finalizing this order. This list can be modified.
     */
    public List<MockAuthorization> getAuthorizations() {
        return authorizations;
    }

    /**
     * Returns a {@link List} of all {@link Identifier} in this order. This list is
     * unmodifiable.
     */
    public List<Identifier> getIdentifiers() {
        return identifiers;
    }

    @Override
    public URL getLocation() {
        return buildUrl("order", getUniqueId());
    }

    /**
     * Returns the {@link URL} of the finalization endpoint.
     */
    public URL getFinalizeLocation() {
        return buildUrl("order", getUniqueId(), "finalize");
    }

    /**
     * Returns the {@link URL} of the certificate.
     */
    public URL getCertificateLocation() {
        return buildUrl("certificate", getUniqueId());
    }

    /**
     * Detaches this {@link MockOrder} from the {@link Repository}.
     *
     * @param repository
     *         {@link Repository} to remove the order from.
     */
    public void detach(Repository repository) {
        repository.removeController(getFinalizeLocation());
        repository.removeController(getCertificateLocation());
        repository.removeResource(this);
    }

    @Override
    public JSON toJSON() {
        JSONBuilder jb = new JSONBuilder();
        jb.put("status", getStatus().name().toLowerCase());
        if (getExpires() != null) {
            jb.put("expires", getExpires());
        }
        jb.array("identifiers", getIdentifiers().stream()
                .map(Identifier::toMap)
                .collect(toList())
        );
        if (getNotBefore() != null) {
            jb.put("notBefore", getNotBefore());
        }
        if (getNotAfter() != null) {
            jb.put("notAfter", getNotAfter());
        }
        Problem err = getError();
        if (err != null) {
            jb.put("error", err.asJSON().toMap());
        }
        jb.put("authorizations", getAuthorizations().stream()
                .map(MockAuthorization::getLocation)
                .collect(toList())
        );
        jb.put("finalize", getFinalizeLocation());
        if (getCertificate() != null) {
            jb.put("certificate", getCertificateLocation());
        }
        return jb.toJSON();
    }

}
