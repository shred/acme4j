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
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.JoseUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder for registering a new account with the CA.
 * <p>
 * You need to create a new key pair and set it via {@link #useKeyPair(KeyPair)}. Your
 * account will be identified by the public part of that key pair, so make sure to store
 * it safely! There is no automatic way to regain access to your account if the key pair
 * is lost.
 * <p>
 * Depending on the CA you register with, you might need to give additional information.
 * <ul>
 *     <li>You might need to agree to the terms of service via
 *     {@link #agreeToTermsOfService()}.</li>
 *     <li>You might need to give at least one contact URI.</li>
 *     <li>You might need to provide a key identifier (e.g. your customer number) and
 *     a shared secret via {@link #withKeyIdentifier(String, SecretKey)}.</li>
 * </ul>
 * <p>
 * It is not possible to modify an existing account with the {@link AccountBuilder}. To
 * modify an existing account, use {@link Account#modify()} and
 * {@link Account#changeKey(KeyPair)}.
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
     * <p>
     * A contact URI may be e.g. an email address or a phone number. It depends on the CA
     * what kind of contact URIs are accepted, and how many must be provided as minimum.
     *
     * @param contact
     *         Contact URI
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
     *         Contact URI as string
     * @return itself
     * @throws IllegalArgumentException
     *         if there is a syntax error in the URI string
     */
    public AccountBuilder addContact(String contact) {
        addContact(URI.create(contact));
        return this;
    }

    /**
     * Add an email address to the list of contacts.
     * <p>
     * This is a convenience call for {@link #addContact(String)} that doesn't require
     * to prepend the "mailto" scheme to an email address.
     *
     * @param email
     *         Contact email without "mailto" scheme (e.g. test@gmail.com)
     * @return itself
     * @throws IllegalArgumentException
     *         if there is a syntax error in the URI string
     */
    public AccountBuilder addEmail(String email) {
        if (email.startsWith("mailto:")) {
            addContact(email);
        } else {
            addContact("mailto:" + email);
        }
        return this;
    }

    /**
     * Documents that the user has agreed to the terms of service.
     * <p>
     * If the CA requires the user to agree to the terms of service, it is your
     * responsibility to present them to the user, and actively ask for their agreement. A
     * link to the terms of service is provided via
     * {@code session.getMetadata().getTermsOfService()}.
     *
     * @return itself
     */
    public AccountBuilder agreeToTermsOfService() {
        this.termsOfServiceAgreed = true;
        return this;
    }

    /**
     * Signals that only an existing account should be returned. The server will not
     * create a new account if the key is not known.
     * <p>
     * If you have lost your account's location URL, but still have your account's key
     * pair, you can register your account again with the same key, and use
     * {@link #onlyExisting()} to make sure that your existing account is returned. If
     * your key is unknown to the server, an error is thrown once the account is to be
     * created.
     *
     * @return itself
     */
    public AccountBuilder onlyExisting() {
        this.onlyExisting = true;
        return this;
    }

    /**
     * Sets the {@link KeyPair} to be used for this account.
     * <p>
     * Only the public key of the pair is sent to the server for registration. acme4j will
     * never send the private key part.
     * <p>
     * Make sure to store your key pair safely after registration! There is no automatic
     * way to regain access to your account if the key pair is lost.
     *
     * @param keyPair
     *         Account's {@link KeyPair}
     * @return itself
     */
    public AccountBuilder useKeyPair(KeyPair keyPair) {
        this.keyPair = requireNonNull(keyPair, "keyPair");
        return this;
    }

    /**
     * Sets a Key Identifier and MAC key provided by the CA. Use this if your CA requires
     * an individual account identification (e.g. your customer number) and a shared
     * secret for registration. See the documentation of your CA about how to retrieve the
     * key identifier and MAC key.
     *
     * @param kid
     *         Key Identifier
     * @param macKey
     *         MAC key
     * @return itself
     * @see #withKeyIdentifier(String, String)
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
     * an individual account identification (e.g. your customer number) and a shared
     * secret for registration. See the documentation of your CA about how to retrieve the
     * key identifier and MAC key.
     * <p>
     * This is a convenience call of {@link #withKeyIdentifier(String, SecretKey)} that
     * accepts a base64url encoded MAC key, so both parameters can be passed in as
     * strings.
     *
     * @param kid
     *         Key Identifier
     * @param encodedMacKey
     *         Base64url encoded MAC key.
     * @return itself
     * @see #withKeyIdentifier(String, SecretKey)
     */
    public AccountBuilder withKeyIdentifier(String kid, String encodedMacKey) {
        var encodedKey = AcmeUtils.base64UrlDecode(requireNonNull(encodedMacKey, "encodedMacKey"));
        return withKeyIdentifier(kid, new SecretKeySpec(encodedKey, "HMAC"));
    }

    /**
     * Creates a new account.
     * <p>
     * Use this method to finally create your account with the given parameters. Do not
     * use the {@link AccountBuilder} after invoking this method.
     *
     * @param session
     *         {@link Session} to be used for registration
     * @return {@link Account} referring to the new account
     * @see #createLogin(Session)
     */
    public Account create(Session session) throws AcmeException {
        return createLogin(session).getAccount();
    }

    /**
     * Creates a new account.
     * <p>
     * This method is identical to {@link #create(Session)}, but returns a {@link Login}
     * that is ready to be used.
     *
     * @param session
     *         {@link Session} to be used for registration
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

            var login = new Login(conn.getLocation(), keyPair, session);
            login.getAccount().setJSON(conn.readJsonResponse());
            return login;
        }
    }

}
