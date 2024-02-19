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
import static org.shredzone.acme4j.toolbox.AcmeUtils.getRenewalUniqueIdentifier;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A {@link Login} into an account.
 * <p>
 * A login is bound to a {@link Session}. However, a {@link Session} can handle multiple
 * logins in parallel.
 * <p>
 * To create a login, you need to specify the location URI of the {@link Account}, and
 * need to provide the {@link KeyPair} the account was created with. If the account's
 * location URL is unknown, the account can be re-registered with the
 * {@link AccountBuilder}, using {@link AccountBuilder#onlyExisting()} to make sure that
 * no new account will be created. If the key pair was lost though, there is no automatic
 * way to regain access to your account, and you have to contact your CA's support hotline
 * for assistance.
 * <p>
 * Note that {@link Login} objects are intentionally not serializable, as they contain a
 * keypair and volatile data. On distributed systems, you can create a {@link Login} to
 * the same account for every service instance.
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
     * Creates a new instance of an existing {@link Authorization} and binds it to this
     * login.
     *
     * @param location
     *         Location of the Authorization
     * @return {@link Authorization} bound to the login
     */
    public Authorization bindAuthorization(URL location) {
        return new Authorization(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of an existing {@link Certificate} and binds it to this
     * login.
     *
     * @param location
     *         Location of the Certificate
     * @return {@link Certificate} bound to the login
     */
    public Certificate bindCertificate(URL location) {
        return new Certificate(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of an existing {@link Order} and binds it to this login.
     *
     * @param location
     *         Location URL of the order
     * @return {@link Order} bound to the login
     */
    public Order bindOrder(URL location) {
        return new Order(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of an existing {@link RenewalInfo} and binds it to this
     * login.
     *
     * @param location
     *         Location URL of the renewal info
     * @return {@link RenewalInfo} bound to the login
     * @since 3.0.0
     */
    public RenewalInfo bindRenewalInfo(URL location) {
        return new RenewalInfo(this, requireNonNull(location, "location"));
    }

    /**
     * Creates a new instance of an existing {@link RenewalInfo} and binds it to this
     * login.
     *
     * @param certificate
     *         {@link X509Certificate} to get the {@link RenewalInfo} for
     * @return {@link RenewalInfo} bound to the login
     * @draft This method is currently based on an RFC draft. It may be changed or removed
     * without notice to reflect future changes to the draft. SemVer rules do not apply
     * here.
     * @since 3.2.0
     */
    public RenewalInfo bindRenewalInfo(X509Certificate certificate) throws AcmeException {
        try {
            var url = getSession().resourceUrl(Resource.RENEWAL_INFO).toExternalForm();
            if (!url.endsWith("/")) {
                url += '/';
            }
            url += getRenewalUniqueIdentifier(certificate);
            return bindRenewalInfo(new URL(url));
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException("Invalid RenewalInfo URL", ex);
        }
    }

    /**
     * Creates a new instance of an existing {@link Challenge} and binds it to this
     * login. Use this method only if the resulting challenge type is unknown.
     *
     * @param location
     *         Location URL of the challenge
     * @return {@link Challenge} bound to the login
     * @since 2.8
     * @see #bindChallenge(URL, Class)
     */
    public Challenge bindChallenge(URL location) {
        try (var connect = session.connect()) {
            connect.sendSignedPostAsGetRequest(location, this);
            return createChallenge(connect.readJsonResponse());
        } catch (AcmeException ex) {
            throw new AcmeLazyLoadingException(Challenge.class, location, ex);
        }
    }

    /**
     * Creates a new instance of an existing {@link Challenge} and binds it to this
     * login. Use this method if the resulting challenge type is known.
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
        var challenge = bindChallenge(location);
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
        var challenge = session.provider().createChallenge(this, data);
        if (challenge == null) {
            throw new AcmeProtocolException("Could not create challenge for: " + data);
        }
        return challenge;
    }

    /**
     * Creates a builder for a new {@link Order}.
     *
     * @return {@link OrderBuilder} object
     * @since 3.0.0
     */
    public OrderBuilder newOrder() {
        return new OrderBuilder(this);
    }

    /**
     * Sets a different {@link KeyPair}. The new key pair is only used locally in this
     * instance, but is not set on server side!
     */
    protected void setKeyPair(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
    }

}
