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

import static java.util.stream.Collectors.toUnmodifiableList;

import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.ResourceIterator;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.JoseUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A representation of an account at the ACME server.
 */
public class Account extends AcmeJsonResource {
    private static final long serialVersionUID = 7042863483428051319L;
    private static final Logger LOG = LoggerFactory.getLogger(Account.class);

    private static final String KEY_TOS_AGREED = "termsOfServiceAgreed";
    private static final String KEY_ORDERS = "orders";
    private static final String KEY_CONTACT = "contact";
    private static final String KEY_STATUS = "status";
    private static final String KEY_EXTERNAL_ACCOUNT_BINDING = "externalAccountBinding";

    protected Account(Login login) {
        super(login, login.getAccountLocation());
    }

    /**
     * Returns if the user agreed to the terms of service.
     *
     * @return {@code true} if the user agreed to the terms of service. May be
     *         empty if the server did not provide such an information.
     */
    public Optional<Boolean> getTermsOfServiceAgreed() {
        return getJSON().get(KEY_TOS_AGREED).map(Value::asBoolean);
    }

    /**
     * List of registered contact addresses (emails, phone numbers etc).
     * <p>
     * This list is unmodifiable. Use {@link #modify()} to change the contacts. May be
     * empty, but is never {@code null}.
     */
    public List<URI> getContacts() {
        return getJSON().get(KEY_CONTACT)
                .asArray()
                .stream()
                .map(Value::asURI)
                .collect(toUnmodifiableList());
    }

    /**
     * Returns the current status of the account.
     * <p>
     * Possible values are: {@link Status#VALID}, {@link Status#DEACTIVATED},
     * {@link Status#REVOKED}.
     */
    public Status getStatus() {
        return getJSON().get(KEY_STATUS).asStatus();
    }

    /**
     * Returns {@code true} if the account is bound to an external non-ACME account.
     *
     * @since 2.8
     */
    public boolean hasExternalAccountBinding() {
        return getJSON().contains(KEY_EXTERNAL_ACCOUNT_BINDING);
    }

    /**
     * Returns the key identifier of the external non-ACME account. If this account is
     * not bound to an external account, the result is empty.
     *
     * @since 2.8
     */
    public Optional<String> getKeyIdentifier() {
        return getJSON().get(KEY_EXTERNAL_ACCOUNT_BINDING)
                .optional().map(Value::asObject)
                .map(j -> j.get("protected")).map(Value::asEncodedObject)
                .map(j -> j.get("kid")).map(Value::asString);
    }

    /**
     * Returns an {@link Iterator} of all {@link Order} belonging to this
     * {@link Account}.
     * <p>
     * Using the iterator will initiate one or more requests to the ACME server.
     *
     * @return {@link Iterator} instance that returns {@link Order} objects in no specific
     * sorting order. {@link Iterator#hasNext()} and {@link Iterator#next()} may throw
     * {@link AcmeProtocolException} if a batch of authorization URIs could not be fetched
     * from the server.
     */
    public Iterator<Order> getOrders() {
        var ordersUrl = getJSON().get(KEY_ORDERS).optional().map(Value::asURL);
        if (ordersUrl.isEmpty()) {
            // Let's Encrypt does not provide this field at the moment, although it's required.
            // See https://github.com/letsencrypt/boulder/issues/3335
            throw new AcmeNotSupportedException("getOrders()");
        }
        return new ResourceIterator<>(getLogin(), KEY_ORDERS, ordersUrl.get(), Login::bindOrder);
    }

    /**
     * Creates a builder for a new {@link Order}.
     *
     * @return {@link OrderBuilder} object
     */
    public OrderBuilder newOrder() {
        return getLogin().newOrder();
    }

    /**
     * Pre-authorizes a domain. The CA will check if it accepts the domain for
     * certification, and returns the necessary challenges.
     * <p>
     * Some servers may not allow pre-authorization.
     * <p>
     * It is not possible to pre-authorize wildcard domains.
     *
     * @param domain
     *            Domain name to be pre-authorized. IDN names are accepted and will be ACE
     *            encoded automatically.
     * @return {@link Authorization} object for this domain
     * @throws AcmeException
     *             if the server does not allow pre-authorization
     * @throws AcmeServerException
     *             if the server allows pre-authorization, but will refuse to issue a
     *             certificate for this domain
     */
    public Authorization preAuthorizeDomain(String domain) throws AcmeException {
        Objects.requireNonNull(domain, "domain");
        if (domain.isEmpty()) {
            throw new IllegalArgumentException("domain must not be empty");
        }
        return preAuthorize(Identifier.dns(domain));
    }

    /**
     * Pre-authorizes an {@link Identifier}. The CA will check if it accepts the
     * identifier for certification, and returns the necessary challenges.
     * <p>
     * Some servers may not allow pre-authorization.
     * <p>
     * It is not possible to pre-authorize wildcard domains.
     *
     * @param identifier
     *            {@link Identifier} to be pre-authorized.
     * @return {@link Authorization} object for this identifier
     * @throws AcmeException
     *             if the server does not allow pre-authorization
     * @throws AcmeServerException
     *             if the server allows pre-authorization, but will refuse to issue a
     *             certificate for this identifier
     * @since 2.3
     */
    public Authorization preAuthorize(Identifier identifier) throws AcmeException {
        Objects.requireNonNull(identifier, "identifier");

        var newAuthzUrl = getSession().resourceUrl(Resource.NEW_AUTHZ);

        LOG.debug("preAuthorize {}", identifier);
        try (var conn = getSession().connect()) {
            var claims = new JSONBuilder();
            claims.put("identifier", identifier.toMap());

            conn.sendSignedRequest(newAuthzUrl, claims, getLogin());

            var authLocation = conn.getLocation()
                    .orElseThrow(() -> new AcmeProtocolException("Server did not provide an authorization location"));
            var auth = getLogin().bindAuthorization(authLocation);
            auth.setJSON(conn.readJsonResponse());
            return auth;
        }
    }

    /**
     * Changes the {@link KeyPair} associated with the account.
     * <p>
     * After a successful call, the new key pair is already set in the associated
     * {@link Login}. The old key pair can be discarded.
     *
     * @param newKeyPair
     *         new {@link KeyPair} to be used for identifying this account
     */
    public void changeKey(KeyPair newKeyPair) throws AcmeException {
        Objects.requireNonNull(newKeyPair, "newKeyPair");
        if (Arrays.equals(getLogin().getKeyPair().getPrivate().getEncoded(),
                        newKeyPair.getPrivate().getEncoded())) {
            throw new IllegalArgumentException("newKeyPair must actually be a new key pair");
        }

        LOG.debug("key-change");

        try (var conn = getSession().connect()) {
            var keyChangeUrl = getSession().resourceUrl(Resource.KEY_CHANGE);

            var payloadClaim = new JSONBuilder();
            payloadClaim.put("account", getLocation());
            payloadClaim.putKey("oldKey", getLogin().getKeyPair().getPublic());

            var jose = JoseUtils.createJoseRequest(keyChangeUrl, newKeyPair,
                    payloadClaim, null, null);

            conn.sendSignedRequest(keyChangeUrl, jose, getLogin());

            getLogin().setKeyPair(newKeyPair);
        }
    }

    /**
     * Permanently deactivates an account. Related certificates may still be valid after
     * account deactivation, and need to be revoked separately if neccessary.
     * <p>
     * A deactivated account cannot be reactivated!
     */
    public void deactivate() throws AcmeException {
        LOG.debug("deactivate");
        try (var conn = getSession().connect()) {
            var claims = new JSONBuilder();
            claims.put(KEY_STATUS, "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getLogin());
            setJSON(conn.readJsonResponse());
        }
    }

    /**
     * Modifies the account data of the account.
     *
     * @return {@link EditableAccount} where the account can be modified
     */
    public EditableAccount modify() {
        return new EditableAccount();
    }

    /**
     * Provides editable properties of an {@link Account}.
     */
    public class EditableAccount {
        private final List<URI> editContacts = new ArrayList<>();

        private EditableAccount() {
            editContacts.addAll(Account.this.getContacts());
        }

        /**
         * Returns the list of all contact URIs for modification. Use the {@link List}
         * methods to modify the contact list.
         * <p>
         * The modified list is not validated. If you change entries, you have to make
         * sure that they are valid according to the RFC. It is recommended to use
         * the {@code addContact()} methods below to add new contacts to the list.
         */
        public List<URI> getContacts() {
            return editContacts;
        }

        /**
         * Adds a new Contact to the account.
         *
         * @param contact
         *            Contact URI
         * @return itself
         */
        public EditableAccount addContact(URI contact) {
            AcmeUtils.validateContact(contact);
            editContacts.add(contact);
            return this;
        }

        /**
         * Adds a new Contact to the account.
         * <p>
         * This is a convenience call for {@link #addContact(URI)}.
         *
         * @param contact
         *            Contact URI as string
         * @return itself
         */
        public EditableAccount addContact(String contact) {
            addContact(URI.create(contact));
            return this;
        }

        /**
         * Adds a new Contact email to the account.
         * <p>
         * This is a convenience call for {@link #addContact(String)} that doesn't
         * require to prepend the email address with the "mailto" scheme.
         *
         * @param email
         *            Contact email without "mailto" scheme (e.g. test@gmail.com)
         * @return itself
         */
        public EditableAccount addEmail(String email) {
            addContact("mailto:" + email);
            return this;
        }

        /**
         * Commits the changes and updates the account.
         */
        public void commit() throws AcmeException {
            LOG.debug("modify/commit");
            try (var conn = getSession().connect()) {
                var claims = new JSONBuilder();
                if (!editContacts.isEmpty()) {
                    claims.put(KEY_CONTACT, editContacts);
                }

                conn.sendSignedRequest(getLocation(), claims, getLogin());
                setJSON(conn.readJsonResponse());
            }
        }
    }

}
