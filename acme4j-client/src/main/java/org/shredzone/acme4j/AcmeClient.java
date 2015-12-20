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
     * @param account
     *            {@link Account} to register
     * @param registration
     *            {@link Registration} containing registration data
     */
    void newRegistration(Account account, Registration registration) throws AcmeException;

    /**
     * Modifies an existing account.
     *
     * @param account
     *            {@link Account} that is registered
     * @param registration
     *            {@link Registration} containing updated registration data. Set the
     *            account location via {@link Registration#setLocation(URI)}!
     */
    void modifyRegistration(Account account, Registration registration) throws AcmeException;

    /**
     * Creates a new {@link Authorization} for a domain.
     *
     * @param account
     *            {@link Account} the authorization is related to
     * @param auth
     *            {@link Authorization} containing the domain name
     */
    void newAuthorization(Account account, Authorization auth) throws AcmeException;

    /**
     * Triggers a {@link Challenge}. The ACME server is requested to validate the
     * response. Note that the validation is performed asynchronously.
     *
     * @param account
     *            {@link Account} to be used for conversation
     * @param challenge
     *            {@link Challenge} to trigger
     */
    void triggerChallenge(Account account, Challenge challenge) throws AcmeException;

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
     * @param account
     *            {@link Account} to be used for conversation
     * @param csr
     *            PKCS#10 Certificate Signing Request to be sent to the server
     * @return {@link URI} the certificate can be downloaded from
     */
    URI requestCertificate(Account account, byte[] csr) throws AcmeException;

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
     * @param account
     *            {@link Account} to be used for conversation
     * @param certificate
     *            Certificate to revoke
     */
    void revokeCertificate(Account account, X509Certificate certificate) throws AcmeException;

}
