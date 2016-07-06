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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a registration at the ACME server.
 *
 * @author Richard "Shred" Körber
 */
public class Registration extends AcmeResource {
    private static final long serialVersionUID = -8177333806740391140L;
    private static final Logger LOG = LoggerFactory.getLogger(Registration.class);

    private final List<URI> contacts = new ArrayList<>();
    private URI agreement;
    private Status status;

    /**
     * Creates a new instance of {@link Registration} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location URI of the registration
     */
    public static Registration bind(Session session, URI location) {
        return new Registration(session, location);
    }

    protected Registration(Session session, URI location) {
        super(session);
        setLocation(location);
    }

    protected Registration(Session session, URI location, URI agreement) {
        super(session);
        setLocation(location);
        this.agreement = agreement;
    }

    /**
     * Returns the URI of the agreement document the user is required to accept.
     */
    public URI getAgreement() {
        return agreement;
    }

    /**
     * List of contact addresses (emails, phone numbers etc).
     */
    public List<URI> getContacts() {
        return Collections.unmodifiableList(contacts);
    }

    /**
     * Returns the current status of the registration.
     */
    public Status getStatus() {
        return status;
    }

    /**
     * Updates the registration to the current account status.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");

            int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
            if (rc != HttpURLConnection.HTTP_CREATED && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            Map<String, Object> json = conn.readJsonResponse();
            unmarshal(json, conn);
         } catch (IOException ex) {
             throw new AcmeNetworkException(ex);
         }
    }

    /**
     * Authorizes a domain. The domain is associated with this registration.
     *
     * @param domain
     *            Domain name to be authorized
     * @return {@link Authorization} object for this domain
     */
    public Authorization authorizeDomain(String domain) throws AcmeException {
        if (domain == null || domain.isEmpty()) {
            throw new NullPointerException("domain must not be empty or null");
        }

        LOG.debug("authorizeDomain {}", domain);
        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_AUTHZ);
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", domain);

            int rc = conn.sendSignedRequest(getSession().resourceUri(Resource.NEW_AUTHZ), claims, getSession());
            if (rc != HttpURLConnection.HTTP_CREATED) {
                conn.throwAcmeException();
            }

            Map<String, Object> json = conn.readJsonResponse();

            Authorization auth = new Authorization(getSession(), conn.getLocation());
            auth.unmarshalAuthorization(json);
            return auth;
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Requests a certificate for the given CSR.
     * <p>
     * All domains given in the CSR must be authorized before.
     *
     * @param csr
     *            PKCS#10 Certificate Signing Request to be sent to the server
     * @return The {@link Certificate}
     */
    public Certificate requestCertificate(byte[] csr) throws AcmeException {
        if (csr == null) {
            throw new NullPointerException("csr must not be null");
        }

        LOG.debug("requestCertificate");
        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_CERT);
            claims.putBase64("csr", csr);

            int rc = conn.sendSignedRequest(getSession().resourceUri(Resource.NEW_CERT), claims, getSession());
            if (rc != HttpURLConnection.HTTP_CREATED && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            X509Certificate cert = null;
            if (rc == HttpURLConnection.HTTP_CREATED) {
                cert = conn.readCertificate();
            }

            URI chainCertUri = conn.getLink("up");

            return new Certificate(getSession(), conn.getLocation(), chainCertUri, cert);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Changes the {@link KeyPair} associated with the registration. After a successful
     * call, the new key pair is used, and the old key pair can be disposed.
     *
     * @param newKeyPair
     *            new {@link KeyPair} to be used for identifying this account
     */
    public void changeKey(KeyPair newKeyPair) throws AcmeException {
        if (newKeyPair == null) {
            throw new NullPointerException("newKeyPair must not be null");
        }
        if (Arrays.equals(getSession().getKeyPair().getPrivate().getEncoded(),
                        newKeyPair.getPrivate().getEncoded())) {
            throw new IllegalArgumentException("newKeyPair must actually be a new key pair");
        }

        LOG.debug("changeKey");

        String rollover;
        try {
            ClaimBuilder newKeyClaim = new ClaimBuilder();
            newKeyClaim.putResource("reg");
            newKeyClaim.putBase64("newKey", SignatureUtils.jwkThumbprint(newKeyPair.getPublic()));

            final PublicJsonWebKey oldKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(getSession().getKeyPair().getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(newKeyClaim.toString());
            jws.getHeaders().setJwkHeaderValue("jwk", oldKeyJwk);
            jws.setAlgorithmHeaderValue(SignatureUtils.keyAlgorithm(oldKeyJwk));
            jws.setKey(getSession().getKeyPair().getPrivate());
            jws.sign();

            rollover = jws.getCompactSerialization();
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Cannot sign newKey", ex);
        }

        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            claims.put("rollover", rollover);

            getSession().setKeyPair(newKeyPair);
            int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
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
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            claims.put("status", "deactivated");

            int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Sets registration properties according to the given JSON data.
     *
     * @param json
     *            JSON data
     * @param conn
     *            {@link Connection} with headers to be evaluated
     */
    @SuppressWarnings("unchecked")
    private void unmarshal(Map<String, Object> json, Connection conn) {
        if (json.containsKey("agreement")) {
            try {
                this.agreement = new URI((String) json.get("agreement"));
            } catch (ClassCastException | URISyntaxException ex) {
                throw new AcmeProtocolException("Illegal agreement URI", ex);
            }
        }

        if (json.containsKey("contact")) {
            contacts.clear();
            for (Object c : (Collection<Object>) json.get("contact")) {
                try {
                    contacts.add(new URI((String) c));
                } catch (ClassCastException | URISyntaxException ex) {
                    throw new AcmeProtocolException("Illegal contact URI", ex);
                }
            }
        }

        if (json.containsKey("status")) {
            this.status = Status.parse((String) json.get("status"));
        }

        URI location = conn.getLocation();
        if (location != null) {
            setLocation(location);
        }

        URI tos = conn.getLink("terms-of-service");
        if (tos != null) {
            this.agreement = tos;
        }
    }

    /**
     * Modifies the registration data of the account.
     *
     * @return {@link EditableRegistration} where the account can be modified
     */
    public EditableRegistration modify() {
        return new EditableRegistration();
    }

    /**
     * Editable {@link Registration}.
     */
    public class EditableRegistration {
        private final List<URI> editContacts = new ArrayList<>();
        private URI editAgreement;

        public EditableRegistration() {
            editContacts.addAll(Registration.this.contacts);
            editAgreement = Registration.this.agreement;
        }

        /**
         * Returns the list of all contact URIs for modification. Use the {@link List}
         * methods to modify the contact list.
         */
        public List<URI> getContacts() {
            return editContacts;
        }

        /**
         * Adds a new Contact to the registration.
         *
         * @param contact
         *            Contact URI
         */
        public EditableRegistration addContact(URI contact) {
            editContacts.add(contact);
            return this;
        }

        /**
         * Adds a new Contact to the registration.
         * <p>
         * This is a convenience call for {@link #addContact(URI)}.
         *
         * @param contact
         *            Contact URI as string
         */
        public EditableRegistration addContact(String contact) {
            addContact(URI.create(contact));
            return this;
        }

        /**
         * Sets a new agreement URI.
         *
         * @param agreement
         *            New agreement URI
         */
        public EditableRegistration setAgreement(URI agreement) {
            this.editAgreement = agreement;
            return this;
        }

        /**
         * Commits the changes and updates the account.
         */
        public void commit() throws AcmeException {
            LOG.debug("modify/commit");
            try (Connection conn = getSession().provider().connect()) {
                ClaimBuilder claims = new ClaimBuilder();
                claims.putResource("reg");
                if (!editContacts.isEmpty()) {
                    claims.put("contact", editContacts);
                }
                if (editAgreement != null) {
                    claims.put("agreement", editAgreement);
                }

                int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
                if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                    conn.throwAcmeException();
                }

                Map<String, Object> json = conn.readJsonResponse();
                unmarshal(json, conn);
            } catch (IOException ex) {
                throw new AcmeNetworkException(ex);
            }
        }
    }

}
