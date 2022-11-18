/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.JoseUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder for registering a new account.
 */
public class AccountBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(AccountBuilder.class);

    private final List<URI> contacts = new ArrayList<>();
    private @Nullable Boolean termsOfServiceAgreed;
    private @Nullable Boolean onlyExisting;
    private @Nullable String keyIdentifier;
    private @Nullable KeyPair keyPair;
    private @Nullable SecretKey macKey;

    /**
     * Add a contact URI to the list of contacts.
     *
     * @param contact
     *            Contact URI
     * @return itself
     */
    public AccountBuilder addContact(URI contact) {
        AcmeUtils.validateContact(contact);
        contacts.add(contact);
        return this;
    }

    /**
     * Add a contact address to the list of contacts.
     * <p>
     * This is a convenience call for {@link #addContact(URI)}.
     *
     * @param contact
     *            Contact URI as string
     * @throws IllegalArgumentException
     *             if there is a syntax error in the URI string
     * @return itself
     */
    public AccountBuilder addContact(String contact) {
        addContact(URI.create(contact));
        return this;
    }

    /**
     * Add a email address to the list of contacts.
     * <p>
     * This is a convenience call for {@link #addContact(String)} that doesn't
     * require from you attach "mailto" scheme before email address.
     *
     * @param email
     *             Contact email without "mailto" scheme (e.g. test@gmail.com)
     * @throws IllegalArgumentException
     *             if there is a syntax error in the URI string
     * @return itself
     */
    public AccountBuilder addEmail(String email) {
        addContact("mailto:" + email);
        return this;
    }

    /**
     * Signals that the user agrees to the terms of service.
     *
     * @return itself
     */
    public AccountBuilder agreeToTermsOfService() {
        this.termsOfServiceAgreed = true;
        return this;
    }

    /**
     * Signals that only an existing account should be returned. The server will not
     * create a new account if the key is not known. This is useful if you only have your
     * account's key pair available, but not your account's location URL.
     *
     * @return itself
     */
    public AccountBuilder onlyExisting() {
        this.onlyExisting = true;
        return this;
    }

    /**
     * Sets the {@link KeyPair} to be used for this account.
     *
     * @param keyPair
     *            Account's {@link KeyPair}
     * @return itself
     */
    public AccountBuilder useKeyPair(KeyPair keyPair) {
        this.keyPair = requireNonNull(keyPair, "keyPair");
        return this;
    }

    /**
     * Sets a Key Identifier and MAC key provided by the CA. Use this if your CA requires
     * an individual account identification, e.g. your customer number.
     *
     * @param kid
     *            Key Identifier
     * @param macKey
     *            MAC key
     * @return itself
     */
    public AccountBuilder withKeyIdentifier(String kid, SecretKey macKey) {
        if (kid != null && kid.isEmpty()) {
            throw new IllegalArgumentException("kid must not be empty");
        }
        this.macKey = requireNonNull(macKey, "macKey");
        this.keyIdentifier = kid;
        return this;
    }

    /**
     * Sets a Key Identifier and MAC key provided by the CA. Use this if your CA requires
     * an individual account identification, e.g. your customer number.
     *
     * @param kid
     *            Key Identifier
     * @param encodedMacKey
     *            Base64url encoded MAC key. It will be decoded for your convenience.
     * @return itself
     */
    public AccountBuilder withKeyIdentifier(String kid, String encodedMacKey) {
        var encodedKey = AcmeUtils.base64UrlDecode(requireNonNull(encodedMacKey, "encodedMacKey"));
        return withKeyIdentifier(kid, new SecretKeySpec(encodedKey, "HMAC"));
    }

    /**
     * Creates a new account.
     *
     * @param session
     *            {@link Session} to be used for registration
     * @return {@link Account} referring to the new account
     */
    public Account create(Session session) throws AcmeException {
        return createLogin(session).getAccount();
    }

    /**
     * Creates a new account.
     * <p>
     * This method returns a ready to use {@link Login} for the new {@link Account}.
     *
     * @param session
     *            {@link Session} to be used for registration
     * @return {@link Login} referring to the new account
     */
    public Login createLogin(Session session) throws AcmeException {
        requireNonNull(session, "session");

        if (keyPair == null) {
            throw new IllegalStateException("Use AccountBuilder.useKeyPair() to set the account's key pair.");
        }

        LOG.debug("create");

        try (var conn = session.connect()) {
            var resourceUrl = session.resourceUrl(Resource.NEW_ACCOUNT);

            var claims = new JSONBuilder();
            if (!contacts.isEmpty()) {
                claims.put("contact", contacts);
            }
            if (termsOfServiceAgreed != null) {
                claims.put("termsOfServiceAgreed", termsOfServiceAgreed);
            }
            if (keyIdentifier != null) {
                claims.put("externalAccountBinding", JoseUtils.createExternalAccountBinding(
                        keyIdentifier, keyPair.getPublic(), macKey, resourceUrl));
            }
            if (onlyExisting != null) {
                claims.put("onlyReturnExisting", onlyExisting);
            }

            conn.sendSignedRequest(resourceUrl, claims, session, keyPair);

            var location = conn.getLocation();
            if (location == null) {
                throw new AcmeProtocolException("Server did not provide an account location");
            }

            var login = new Login(location, keyPair, session);
            login.getAccount().setJSON(conn.readJsonResponse());
            return login;
        }
    }

}
