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

import static org.shredzone.acme4j.util.AcmeUtils.keyAlgorithm;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder for registering a new account.
 */
public class AccountBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(AccountBuilder.class);

    private List<URI> contacts = new ArrayList<>();
    private Boolean termsOfServiceAgreed;
    private Boolean onlyExisting;
    private String keyIdentifier;

    /**
     * Add a contact URI to the list of contacts.
     *
     * @param contact
     *            Contact URI
     * @return itself
     */
    public AccountBuilder addContact(URI contact) {
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
     * Sets a Key Identifier provided by the CA. Use this if your CA requires an
     * individual account identification, e.g. your customer number.
     *
     * @param kid
     *            Key Identifier
     * @return itself
     */
    public AccountBuilder useKeyIdentifier(String kid) {
        if (kid != null && kid.isEmpty()) {
            throw new IllegalArgumentException("kid must not be empty");
        }
        this.keyIdentifier = kid;
        return this;
    }

    /**
     * Creates a new account.
     *
     * @param session
     *            {@link Session} to be used for registration
     * @return {@link Account} referring to the new account
     */
    public Account create(Session session) throws AcmeException {
        LOG.debug("create");

        if (session.getKeyIdentifier() != null) {
            throw new IllegalArgumentException("session already seems to have an Account");
        }

        try (Connection conn = session.provider().connect()) {
            URL resourceUrl = session.resourceUrl(Resource.NEW_ACCOUNT);

            JSONBuilder claims = new JSONBuilder();
            if (!contacts.isEmpty()) {
                claims.put("contact", contacts);
            }
            if (termsOfServiceAgreed != null) {
                claims.put("terms-of-service-agreed", termsOfServiceAgreed);
            }
            if (keyIdentifier != null) {
                claims.put("external-account-binding",
                        createExternalAccountBinding(keyIdentifier, session.getKeyPair(), resourceUrl));
            }
            if (onlyExisting != null) {
                claims.put("only-return-existing", onlyExisting);
            }

            conn.sendSignedRequest(resourceUrl, claims, session, true);
            conn.accept(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED);

            URL location = conn.getLocation();

            Account account = new Account(session, location);
            if (keyIdentifier != null) {
                session.setKeyIdentifier(keyIdentifier);
            }
            account.unmarshal(conn.readJsonResponse());
            return account;
        }
    }

    /**
     * Creates a JSON structure for external account binding.
     *
     * @param kid
     *            Key Identifier provided by the CA
     * @param keyPair
     *            {@link KeyPair} of the account to be created
     * @param resource
     *            "new-account" resource URL
     * @return Created JSON structure
     */
    private Map<String, Object> createExternalAccountBinding(String kid, KeyPair keyPair, URL resource)
                throws AcmeException {
        try {
            PublicJsonWebKey keyJwk = PublicJsonWebKey.Factory.newPublicJwk(keyPair.getPublic());

            JsonWebSignature innerJws = new JsonWebSignature();
            innerJws.setPayload(keyJwk.toJson());
            innerJws.getHeaders().setObjectHeaderValue("url", resource);
            innerJws.getHeaders().setObjectHeaderValue("kid", kid);
            innerJws.setAlgorithmHeaderValue(keyAlgorithm(keyJwk));
            innerJws.setKey(keyPair.getPrivate());
            innerJws.sign();

            JSONBuilder outerClaim = new JSONBuilder();
            outerClaim.put("protected", innerJws.getHeaders().getEncodedHeader());
            outerClaim.put("signature", innerJws.getEncodedSignature());
            outerClaim.put("payload", innerJws.getEncodedPayload());
            return outerClaim.toMap();
        } catch (JoseException ex) {
            throw new AcmeException("Could not create external account binding", ex);
        }
    }

}
