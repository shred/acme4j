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

import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import java.net.HttpURLConnection;
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
import org.shredzone.acme4j.exception.AcmeLazyLoadingException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an account at the ACME server.
 */
public class Account extends AcmeResource {
    private static final long serialVersionUID = 7042863483428051319L;
    private static final Logger LOG = LoggerFactory.getLogger(Account.class);

    private static final String KEY_TOS_AGREED = "termsOfServiceAgreed";
    private static final String KEY_ORDERS = "orders";
    private static final String KEY_CONTACT = "contact";
    private static final String KEY_STATUS = "status";

    private final List<URI> contacts = new ArrayList<>();
    private Status status;
    private Boolean termsOfServiceAgreed;
    private URL orders;
    private boolean loaded = false;

    protected Account(Session session, URL location) {
        super(session);
        setLocation(location);
        session.setKeyIdentifier(location.toString());
    }

    /**
     * Creates a new instance of {@link Account} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location URI of the account
     * @return {@link Account} bound to the session and location
     */
    public static Account bind(Session session, URL location) {
        return new Account(session, location);
    }

    /**
     * Returns if the user agreed to the terms of service.
     *
     * @return {@code true} if the user agreed to the terms of service. May be
     *         {@code null} if the server did not provide such an information.
     */
    public Boolean getTermsOfServiceAgreed() {
        load();
        return termsOfServiceAgreed;
    }

    /**
     * List of contact addresses (emails, phone numbers etc).
     */
    public List<URI> getContacts() {
        load();
        return Collections.unmodifiableList(contacts);
    }

    /**
     * Returns the current status of the account.
     */
    public Status getStatus() {
        load();
        return status;
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
        LOG.debug("getOrders");
        load();
        return new ResourceIterator<>(getSession(), KEY_ORDERS, orders, Order::bind);
    }

    /**
     * Updates the account to the current account status.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();

            conn.sendSignedRequest(getLocation(), claims, getSession());

            unmarshal(conn.readJsonResponse());
         }
    }

    /**
     * Creates a builder for a new {@link Order}.
     *
     * @return {@link OrderBuilder} object
     */
    public OrderBuilder newOrder() throws AcmeException {
        return new OrderBuilder(getSession());
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
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", toAce(domain));

            conn.sendSignedRequest(newAuthzUrl, claims, getSession(), HttpURLConnection.HTTP_CREATED);

            JSON json = conn.readJsonResponse();

            Authorization auth = new Authorization(getSession(), conn.getLocation());
            auth.unmarshalAuthorization(json);
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
        if (Arrays.equals(getSession().getKeyPair().getPrivate().getEncoded(),
                        newKeyPair.getPrivate().getEncoded())) {
            throw new IllegalArgumentException("newKeyPair must actually be a new key pair");
        }

        LOG.debug("key-change");

        try (Connection conn = getSession().provider().connect()) {
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

            conn.sendSignedRequest(keyChangeUrl, outerClaim, getSession());

            getSession().setKeyPair(newKeyPair);
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
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.put(KEY_STATUS, "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getSession());

            unmarshal(conn.readJsonResponse());
        }
    }

    /**
     * Lazily updates the object's state when one of the getters is invoked.
     */
    protected void load() {
        if (!loaded) {
            try {
                update();
            } catch (AcmeRetryAfterException ex) {
                // ignore... The object was still updated.
                LOG.debug("Retry-After", ex);
            } catch (AcmeException ex) {
                throw new AcmeLazyLoadingException(this, ex);
            }
        }
    }

    /**
     * Sets account properties according to the given JSON data.
     *
     * @param json
     *            JSON data
     */
    protected void unmarshal(JSON json) {
        if (json.contains(KEY_TOS_AGREED)) {
            this.termsOfServiceAgreed = json.get(KEY_TOS_AGREED).asBoolean();
        }

        if (json.contains(KEY_CONTACT)) {
            contacts.clear();
            json.get(KEY_CONTACT).asArray().stream()
                    .map(JSON.Value::asURI)
                    .forEach(contacts::add);
        }

        this.orders = json.get(KEY_ORDERS).asURL();

        if (json.contains(KEY_STATUS)) {
            this.status = Status.parse(json.get(KEY_STATUS).asString());
        }

        loaded = true;
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
            editContacts.addAll(Account.this.contacts);
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
            try (Connection conn = getSession().provider().connect()) {
                JSONBuilder claims = new JSONBuilder();
                if (!editContacts.isEmpty()) {
                    claims.put(KEY_CONTACT, editContacts);
                }

                conn.sendSignedRequest(getLocation(), claims, getSession());

                JSON json = conn.readJsonResponse();
                unmarshal(json);
            }
        }
    }

}
