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

import static java.util.stream.Collectors.toList;
import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.ResourceIterator;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSON.Value;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an account at the ACME server.
 */
public class Account extends AcmeJsonResource {
    private static final long serialVersionUID = 7042863483428051319L;
    private static final Logger LOG = LoggerFactory.getLogger(Account.class);

    private static final String KEY_TOS_AGREED = "termsOfServiceAgreed";
    private static final String KEY_ORDERS = "orders";
    private static final String KEY_CONTACT = "contact";
    private static final String KEY_STATUS = "status";

    protected Account(Login login) {
        super(login, login.getAccountLocation());
    }

    /**
     * Returns if the user agreed to the terms of service.
     *
     * @return {@code true} if the user agreed to the terms of service. May be
     *         {@code null} if the server did not provide such an information.
     */
    public Boolean getTermsOfServiceAgreed() {
        return getJSON().get(KEY_TOS_AGREED).optional().map(Value::asBoolean).orElse(null);
    }

    /**
     * List of contact addresses (emails, phone numbers etc).
     */
    public List<URI> getContacts() {
        return Collections.unmodifiableList(getJSON().get(KEY_CONTACT)
                    .asArray()
                    .stream()
                    .map(JSON.Value::asURI)
                    .collect(toList()));
    }

    /**
     * Returns the current status of the account.
     */
    public Status getStatus() {
        return getJSON().get(KEY_STATUS).asStatusOrElse(Status.UNKNOWN);
    }

    /**
     * Returns an {@link Iterator} of all {@link Order} belonging to this {@link Account}.
     * <p>
     * Using the iterator will initiate one or more requests to the ACME server.
     *
     * @return {@link Iterator} instance that returns {@link Order} objects.
     *         {@link Iterator#hasNext()} and {@link Iterator#next()} may throw
     *         {@link AcmeProtocolException} if a batch of authorization URIs could not be
     *         fetched from the server.
     */
    public Iterator<Order> getOrders() throws AcmeException {
        URL ordersUrl = getJSON().get(KEY_ORDERS).asURL();
        return new ResourceIterator<>(getLogin(), KEY_ORDERS, ordersUrl, Login::bindOrder);
    }

    @Override
    public void update() throws AcmeException {
        LOG.debug("update Account");
        try (Connection conn = connect()) {
            conn.sendSignedRequest(getLocation(), new JSONBuilder(), getLogin());
            setJSON(conn.readJsonResponse());
        }
    }

    /**
     * Creates a builder for a new {@link Order}.
     *
     * @return {@link OrderBuilder} object
     */
    public OrderBuilder newOrder() throws AcmeException {
        return new OrderBuilder(getLogin());
    }

    /**
     * Pre-authorizes a domain. The CA will check if it accepts the domain for
     * certification, and returns the necessary challenges.
     * <p>
     * Some servers may not allow pre-authorization.
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

        URL newAuthzUrl = getSession().resourceUrl(Resource.NEW_AUTHZ);
        if (newAuthzUrl == null) {
            throw new AcmeException("Server does not allow pre-authorization");
        }

        LOG.debug("preAuthorizeDomain {}", domain);
        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", toAce(domain));

            conn.sendSignedRequest(newAuthzUrl, claims, getLogin());

            Authorization auth = getLogin().bindAuthorization(conn.getLocation());
            auth.setJSON(conn.readJsonResponse());
            return auth;
        }
    }

    /**
     * Changes the {@link KeyPair} associated with the account.
     * <p>
     * After a successful call, the new key pair is used in the bound {@link Session},
     * and the old key pair can be disposed of.
     *
     * @param newKeyPair
     *            new {@link KeyPair} to be used for identifying this account
     */
    public void changeKey(KeyPair newKeyPair) throws AcmeException {
        Objects.requireNonNull(newKeyPair, "newKeyPair");
        if (Arrays.equals(getLogin().getKeyPair().getPrivate().getEncoded(),
                        newKeyPair.getPrivate().getEncoded())) {
            throw new IllegalArgumentException("newKeyPair must actually be a new key pair");
        }

        LOG.debug("key-change");

        try (Connection conn = connect()) {
            URL keyChangeUrl = getSession().resourceUrl(Resource.KEY_CHANGE);
            PublicJsonWebKey newKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(newKeyPair.getPublic());

            JSONBuilder payloadClaim = new JSONBuilder();
            payloadClaim.put("account", getLocation());
            payloadClaim.putKey("newKey", newKeyPair.getPublic());

            JsonWebSignature innerJws = new JsonWebSignature();
            innerJws.setPayload(payloadClaim.toString());
            innerJws.getHeaders().setObjectHeaderValue("url", keyChangeUrl);
            innerJws.getHeaders().setJwkHeaderValue("jwk", newKeyJwk);
            innerJws.setAlgorithmHeaderValue(keyAlgorithm(newKeyJwk));
            innerJws.setKey(newKeyPair.getPrivate());
            innerJws.sign();

            JSONBuilder outerClaim = new JSONBuilder();
            outerClaim.put("protected", innerJws.getHeaders().getEncodedHeader());
            outerClaim.put("signature", innerJws.getEncodedSignature());
            outerClaim.put("payload", innerJws.getEncodedPayload());

            conn.sendSignedRequest(keyChangeUrl, outerClaim, getLogin());

            getLogin().setKeyPair(newKeyPair);
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Cannot sign key-change", ex);
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
        try (Connection conn = connect()) {
            JSONBuilder claims = new JSONBuilder();
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
     * Editable {@link Account}.
     */
    public class EditableAccount {
        private final List<URI> editContacts = new ArrayList<>();

        private EditableAccount() {
            editContacts.addAll(Account.this.getContacts());
        }

        /**
         * Returns the list of all contact URIs for modification. Use the {@link List}
         * methods to modify the contact list.
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
         * Commits the changes and updates the account.
         */
        public void commit() throws AcmeException {
            LOG.debug("modify/commit");
            try (Connection conn = connect()) {
                JSONBuilder claims = new JSONBuilder();
                if (!editContacts.isEmpty()) {
                    claims.put(KEY_CONTACT, editContacts);
                }

                conn.sendSignedRequest(getLocation(), claims, getLogin());

                setJSON(conn.readJsonResponse());
            }
        }
    }

}
