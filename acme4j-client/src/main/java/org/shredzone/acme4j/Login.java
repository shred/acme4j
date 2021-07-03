/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import static java.util.Objects.requireNonNull;

import java.net.URL;
import java.security.KeyPair;
import java.util.Objects;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Login} is a {@link Session} that is connected to an {@link Account} at the
 * ACME server. It contains the account's {@link KeyPair} and the {@link URL} of the
 * account.
 * <p>
 * Note that {@link Login} objects are not serializable, as they contain a keypair and
 * volatile data.
 */
public class Login {

    private final Session session;
    private final URL accountLocation;
    private final Account account;
    private KeyPair keyPair;

    /**
     * Creates a new {@link Login}.
     *
     * @param accountLocation
     *            Account location {@link URL}
     * @param keyPair
     *            {@link KeyPair} of the account
     * @param session
     *            {@link Session} to be used
     */
    public Login(URL accountLocation, KeyPair keyPair, Session session) {
        this.accountLocation = Objects.requireNonNull(accountLocation, "accountLocation");
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        this.session = Objects.requireNonNull(session, "session");
        this.account = new Account(this);
    }

    /**
     * Gets the {@link Session} that is used.
     */
    public Session getSession() {
        return session;
    }

    /**
     * Gets the {@link KeyPair} of the ACME account.
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * Gets the location {@link URL} of the account.
     */
    public URL getAccountLocation() {
        return accountLocation;
    }

    /**
     * Gets the {@link Account} that is bound to this login.
     *
     * @return {@link Account} bound to the login
     */
    public Account getAccount() {
        return account;
    }

    /**
     * Creates a new instance of {@link Authorization} and binds it to this login.
     *
     * @param location
     *            Location of the Authorization
     * @return {@link Authorization} bound to the login
     */
    public Authorization bindAuthorization(URL location) {
        return new Authorization(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of {@link Certificate} and binds it to this login.
     *
     * @param location
     *            Location of the Certificate
     * @return {@link Certificate} bound to the login
     */
    public Certificate bindCertificate(URL location) {
        return new Certificate(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of {@link Order} and binds it to this login.
     *
     * @param location
     *            Location URL of the order
     * @return {@link Order} bound to the login
     */
    public Order bindOrder(URL location) {
        return new Order(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of {@link Challenge} and binds it to this login.
     *
     * @param location
     *            Location URL of the challenge
     * @return {@link Challenge} bound to the login
     * @since 2.8
     */
    public Challenge bindChallenge(URL location) {
        try {
            Connection connect = session.connect();
            connect.sendSignedPostAsGetRequest(location, this);
            return createChallenge(connect.readJsonResponse());
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(Challenge.class, location, ex);
        }
    }

    /**
     * Creates a new instance of a challenge and binds it to this login.
     *
     * @param location
     *         Location URL of the challenge
     * @param type
     *         Expected challenge type
     * @return Challenge bound to the login
     * @throws AcmeProtocolException
     *         if the challenge found at the location does not match the expected
     *         challenge type.
     * @since 2.12
     */
    public <C extends Challenge> C bindChallenge(URL location, Class<C> type) {
        Challenge challenge = bindChallenge(location);
        if (!type.isInstance(challenge)) {
            throw new AcmeProtocolException("Challenge type " + challenge.getType()
                    + " does not match requested class " + type);
        }
        return type.cast(challenge);
    }

    /**
     * Creates a {@link Challenge} instance for the given challenge data.
     *
     * @param data
     *            Challenge JSON data
     * @return {@link Challenge} instance
     */
    public Challenge createChallenge(JSON data) {
        Challenge challenge = session.provider().createChallenge(this, data);
        if (challenge == null) {
            throw new AcmeProtocolException("Could not create challenge for: " + data);
        }
        return challenge;
    }

    /**
     * Sets a different {@link KeyPair}.
     */
    protected void setKeyPair(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
    }

}
