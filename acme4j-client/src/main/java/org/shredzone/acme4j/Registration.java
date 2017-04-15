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

import static org.shredzone.acme4j.util.AcmeUtils.*;

import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
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
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a registration at the ACME server.
 */
public class Registration extends AcmeResource {
    private static final long serialVersionUID = -8177333806740391140L;
    private static final Logger LOG = LoggerFactory.getLogger(Registration.class);

    private static final String KEY_TOS_AGREED = "terms-of-service-agreed";
    private static final String KEY_AUTHORIZATIONS = "authorizations";
    private static final String KEY_CERTIFICATES = "certificates";
    private static final String KEY_CONTACT = "contact";
    private static final String KEY_STATUS = "status";

    private final List<URI> contacts = new ArrayList<>();
    private Status status;
    private Boolean termsOfServiceAgreed;
    private URI authorizations;
    private URI certificates;
    private boolean loaded = false;

    protected Registration(Session session, URI location) {
        super(session);
        setLocation(location);
    }

    /**
     * Creates a new instance of {@link Registration} and binds it to the {@link Session}.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Location URI of the registration
     * @return {@link Registration} bound to the session and location
     */
    public static Registration bind(Session session, URI location) {
        return new Registration(session, location);
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
     * Returns the current status of the registration.
     */
    public Status getStatus() {
        load();
        return status;
    }

    /**
     * Returns an {@link Iterator} of all {@link Authorization} belonging to this
     * {@link Registration}.
     * <p>
     * Using the iterator will initiate one or more requests to the ACME server.
     *
     * @return {@link Iterator} instance that returns {@link Authorization} objects.
     *         {@link Iterator#hasNext()} and {@link Iterator#next()} may throw
     *         {@link AcmeProtocolException} if a batch of authorization URIs could not be
     *         fetched from the server.
     */
    public Iterator<Authorization> getAuthorizations() throws AcmeException {
        LOG.debug("getAuthorizations");
        load();
        return new ResourceIterator<>(getSession(), KEY_AUTHORIZATIONS, authorizations, Authorization::bind);
    }

    /**
     * Returns an {@link Iterator} of all {@link Certificate} belonging to this
     * {@link Registration}.
     * <p>
     * Using the iterator will initiate one or more requests to the ACME server.
     *
     * @return {@link Iterator} instance that returns {@link Certificate} objects.
     *         {@link Iterator#hasNext()} and {@link Iterator#next()} may throw
     *         {@link AcmeProtocolException} if a batch of certificate URIs could not be
     *         fetched from the server.
     */
    public Iterator<Certificate> getCertificates() throws AcmeException {
        LOG.debug("getCertificates");
        load();
        return new ResourceIterator<>(getSession(), KEY_CERTIFICATES, certificates, Certificate::bind);
    }

    /**
     * Updates the registration to the current account status.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource("reg");

            conn.sendSignedRequest(getLocation(), claims, getSession());
            conn.accept(HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED);

            JSON json = conn.readJsonResponse();
            unmarshal(json, conn);
         }
    }

    /**
     * Authorizes a domain. The domain is associated with this registration.
     * <p>
     * IDN domain names will be ACE encoded automatically.
     *
     * @param domain
     *            Domain name to be authorized
     * @return {@link Authorization} object for this domain
     */
    public Authorization authorizeDomain(String domain) throws AcmeException {
        Objects.requireNonNull(domain, "domain");
        if (domain.isEmpty()) {
            throw new IllegalArgumentException("domain must not be empty");
        }

        LOG.debug("authorizeDomain {}", domain);
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource(Resource.NEW_AUTHZ);
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", toAce(domain));

            conn.sendSignedRequest(getSession().resourceUri(Resource.NEW_AUTHZ), claims, getSession());
            conn.accept(HttpURLConnection.HTTP_CREATED);

            JSON json = conn.readJsonResponse();

            Authorization auth = new Authorization(getSession(), conn.getLocation());
            auth.unmarshalAuthorization(json);
            return auth;
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
        return requestCertificate(csr, null, null);
    }

    /**
     * Requests a certificate for the given CSR.
     * <p>
     * All domains given in the CSR must be authorized before.
     *
     * @param csr
     *            PKCS#10 Certificate Signing Request to be sent to the server
     * @param notBefore
     *            requested value of the notBefore field in the certificate, {@code null}
     *            for default. May be ignored by the server.
     * @param notAfter
     *            requested value of the notAfter field in the certificate, {@code null}
     *            for default. May be ignored by the server.
     * @return The {@link Certificate}
     */
    public Certificate requestCertificate(byte[] csr, Instant notBefore, Instant notAfter)
                throws AcmeException {
        Objects.requireNonNull(csr, "csr");

        LOG.debug("requestCertificate");
        try (Connection conn = getSession().provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.putResource(Resource.NEW_CERT);
            claims.putBase64("csr", csr);
            if (notBefore != null) {
                claims.put("notBefore", notBefore);
            }
            if (notAfter != null) {
                claims.put("notAfter", notAfter);
            }

            conn.sendSignedRequest(getSession().resourceUri(Resource.NEW_CERT), claims, getSession());
            int rc = conn.accept(HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED);

            X509Certificate cert = null;
            if (rc == HttpURLConnection.HTTP_CREATED) {
                try {
                    cert = conn.readCertificate();
                } catch (AcmeProtocolException ex) {
                    LOG.warn("Could not parse attached certificate", ex);
                }
            }

            URI chainCertUri = conn.getLink("up");

            return new Certificate(getSession(), conn.getLocation(), chainCertUri, cert);
        }
    }

    /**
     * Changes the {@link KeyPair} associated with the registration.
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
            URI keyChangeUri = getSession().resourceUri(Resource.KEY_CHANGE);
            PublicJsonWebKey newKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(newKeyPair.getPublic());

            JSONBuilder payloadClaim = new JSONBuilder();
            payloadClaim.put("account", getLocation());
            payloadClaim.putKey("newKey", newKeyPair.getPublic());

            JsonWebSignature innerJws = new JsonWebSignature();
            innerJws.setPayload(payloadClaim.toString());
            innerJws.getHeaders().setObjectHeaderValue("url", keyChangeUri);
            innerJws.getHeaders().setJwkHeaderValue("jwk", newKeyJwk);
            innerJws.setAlgorithmHeaderValue(keyAlgorithm(newKeyJwk));
            innerJws.setKey(newKeyPair.getPrivate());
            innerJws.sign();

            JSONBuilder outerClaim = new JSONBuilder();
            outerClaim.putResource(Resource.KEY_CHANGE); // Let's Encrypt needs the resource here
            outerClaim.put("protected", innerJws.getHeaders().getEncodedHeader());
            outerClaim.put("signature", innerJws.getEncodedSignature());
            outerClaim.put("payload", innerJws.getEncodedPayload());

            conn.sendSignedRequest(keyChangeUri, outerClaim, getSession());
            conn.accept(HttpURLConnection.HTTP_OK);

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
            claims.putResource("reg");
            claims.put(KEY_STATUS, "deactivated");

            conn.sendSignedRequest(getLocation(), claims, getSession());
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED);
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
                throw new AcmeProtocolException("Could not load lazily", ex);
            }
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
    private void unmarshal(JSON json, Connection conn) {
        if (json.contains(KEY_TOS_AGREED)) {
            this.termsOfServiceAgreed = json.get(KEY_TOS_AGREED).asBoolean();
        }

        if (json.contains(KEY_CONTACT)) {
            contacts.clear();
            json.get(KEY_CONTACT).asArray().stream()
                    .map(JSON.Value::asURI)
                    .forEach(contacts::add);
        }

        this.authorizations = json.get(KEY_AUTHORIZATIONS).asURI();
        this.certificates = json.get(KEY_CERTIFICATES).asURI();

        if (json.contains(KEY_STATUS)) {
            this.status = Status.parse(json.get(KEY_STATUS).asString());
        }

        URI location = conn.getLocation();
        if (location != null) {
            setLocation(location);
        }

        loaded = true;
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

        private EditableRegistration() {
            editContacts.addAll(Registration.this.contacts);
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
         * @return itself
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
         * @return itself
         */
        public EditableRegistration addContact(String contact) {
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
                claims.putResource("reg");
                if (!editContacts.isEmpty()) {
                    claims.put(KEY_CONTACT, editContacts);
                }

                conn.sendSignedRequest(getLocation(), claims, getSession());
                conn.accept(HttpURLConnection.HTTP_ACCEPTED);

                JSON json = conn.readJsonResponse();
                unmarshal(json, conn);
            }
        }
    }

}
