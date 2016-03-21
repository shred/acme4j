/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
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

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * An {@link AcmeClient} is used for communication with an ACME server.
 * <p>
 * Use {@link AcmeClientFactory} to generate instances.
 *
 * @author Richard "Shred" Körber
 */
public interface AcmeClient {

    /**
     * Registers a new account.
     *
     * @param registration
     *            {@link Registration} containing registration data
     */
    void newRegistration(Registration registration) throws AcmeException;

    /**
     * Modifies an existing account.
     *
     * @param registration
     *            {@link Registration} containing updated registration data and the
     *            account location URI
     */
    void modifyRegistration(Registration registration) throws AcmeException;

    /**
     * Modifies the account so it is identified with the new {@link KeyPair}.
     * <p>
     * Starting from the next call, {@link Registration} must use the new {@link KeyPair}
     * for identification.
     *
     * @param registration
     *            {@link Registration} containing the account location URI. Other
     *            properties are ignored.
     * @param newKeyPair
     *            new {@link KeyPair} to be used for identifying this account
     */
    void changeRegistrationKey(Registration registration, KeyPair newKeyPair)
                throws AcmeException;

    /**
     * Deletes an account. Related certificates may still be valid after account deletion,
     * and need to be revoked separately if neccessary.
     *
     * @param registration
     *            {@link Registration} to delete
     */
    void deleteRegistration(Registration registration) throws AcmeException;

    /**
     * Creates a new {@link Authorization} for a domain.
     *
     * @param registration
     *            {@link Registration} the authorization is related to
     * @param auth
     *            {@link Authorization} containing the domain name
     */
    void newAuthorization(Registration registration, Authorization auth) throws AcmeException;

    /**
     * Updates an {@link Authorization} to the current server state.
     *
     * @param auth
     *            {@link Authorization} to update
     */
    void updateAuthorization(Authorization auth) throws AcmeException;

    /**
     * Deletes an {@link Authorization}.
     *
     * @param registration
     *            {@link Registration} the authorization is related to
     * @param auth
     *            {@link Authorization} to delete
     */
    void deleteAuthorization(Registration registration, Authorization auth) throws AcmeException;

    /**
     * Triggers a {@link Challenge}. The ACME server is requested to validate the
     * response. Note that the validation is performed asynchronously.
     *
     * @param registration
     *            {@link Registration} to be used for conversation
     * @param challenge
     *            {@link Challenge} to trigger
     */
    void triggerChallenge(Registration registration, Challenge challenge) throws AcmeException;

    /**
     * Updates the {@link Challenge} instance. It contains the current state.
     *
     * @param challenge
     *            {@link Challenge} to update
     */
    void updateChallenge(Challenge challenge) throws AcmeException;

    /**
     * Restores a {@link Challenge} instance if only the challenge URI is known. It
     * contains the current state.
     *
     * @param challengeUri
     *            {@link URI} of the challenge to restore
     * @throws ClassCastException
     *             if the challenge does not match the desired type
     */
    <T extends Challenge> T restoreChallenge(URI challengeUri) throws AcmeException;

    /**
     * Requests a certificate.
     *
     * @param registration
     *            {@link Registration} to be used for conversation
     * @param csr
     *            PKCS#10 Certificate Signing Request to be sent to the server
     * @return {@link URI} the certificate can be downloaded from
     */
    URI requestCertificate(Registration registration, byte[] csr) throws AcmeException;

    /**
     * Downloads a certificate.
     *
     * @param certUri
     *            Certificate {@link URI}
     * @return Downloaded {@link X509Certificate}
     */
    X509Certificate downloadCertificate(URI certUri) throws AcmeException;

    /**
     * Revokes a certificate.
     *
     * @param registration
     *            {@link Registration} to be used for conversation
     * @param certificate
     *            Certificate to revoke
     */
    void revokeCertificate(Registration registration, X509Certificate certificate)
                throws AcmeException;

}
