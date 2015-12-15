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
package org.shredzone.acme4j.impl;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract implementation of the {@link AcmeClient} interface. It contains abstract
 * methods for everything that is provider related.
 *
 * @author Richard "Shred" Körber
 */
public abstract class AbstractAcmeClient implements AcmeClient {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractAcmeClient.class);

    private final Session session = new Session();

    /**
     * Gets the {@link URI} for the given {@link Resource}. This may involve connecting to
     * the server and getting a directory. The result should be cached in the client.
     *
     * @param resource
     *            {@link Resource} to get the {@link URI} of
     * @return {@link URI}, or {@code null} if the server does not offer that resource
     */
    protected abstract URI resourceUri(Resource resource) throws AcmeException;

    /**
     * Creates a {@link Challenge} instance for the given challenge type.
     *
     * @param type
     *            Challenge type
     * @return {@link Challenge} instance
     */
    protected abstract Challenge createChallenge(String type);

    /**
     * Connects to the server's API.
     *
     * @return {@link Connection} instance
     */
    protected abstract Connection createConnection();

    @Override
    public void newRegistration(Account account, Registration registration) throws AcmeException {
        LOG.debug("newRegistration");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_REG);
            if (!registration.getContacts().isEmpty()) {
                claims.put("contact", registration.getContacts());
            }
            if (registration.getAgreementUrl() != null) {
                claims.put("agreement", registration.getAgreementUrl());
            }

            try {
                conn.sendSignedRequest(resourceUri(Resource.NEW_REG), claims, session, account);
            } catch (AcmeServerException ex) {
                URI location = conn.getLocation();
                if (location != null) {
                    registration.setLocation(location);
                }
                throw ex;
            }
        }
    }

    @Override
    public void updateRegistration(Account account, Registration registration) throws AcmeException {
        LOG.debug("updateRegistration");
        if (registration.getLocation() == null) {
            throw new IllegalArgumentException("location must be set. Use newRegistration() if not known.");
        }

        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            if (!registration.getContacts().isEmpty()) {
                claims.put("contact", registration.getContacts());
            }
            if (registration.getAgreementUrl() != null) {
                claims.put("agreement", registration.getAgreementUrl());
            }

            conn.sendSignedRequest(registration.getLocation(), claims, session, account);

            registration.setLocation(conn.getLocation());
        }
    }

    @Override
    public void newAuthorization(Account account, Authorization auth) throws AcmeException {
        LOG.debug("newAuthorization");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_AUTHZ);
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", auth.getDomain());

            conn.sendSignedRequest(resourceUri(Resource.NEW_AUTHZ), claims, session, account);

            Map<String, Object> result = conn.readJsonResponse();

            @SuppressWarnings("unchecked")
            Collection<Map<String, Object>> challenges =
                            (Collection<Map<String, Object>>) result.get("challenges");
            List<Challenge> cr = new ArrayList<>();
            for (Map<String, Object> c : challenges) {
                Challenge ch = createChallenge((String) c.get("type"));
                if (ch != null) {
                    ch.unmarshall(c);
                    cr.add(ch);
                }
            }
            auth.setChallenges(cr);

            @SuppressWarnings("unchecked")
            Collection<List<Number>> combinations =
                            (Collection<List<Number>>) result.get("combinations");
            if (combinations != null) {
                List<List<Challenge>> cmb = new ArrayList<>(combinations.size());
                for (List<Number> c : combinations) {
                    List<Challenge> clist = new ArrayList<>(c.size());
                    for (Number n : c) {
                        clist.add(cr.get(n.intValue()));
                    }
                    cmb.add(clist);
                }
                auth.setCombinations(cmb);
            } else {
                List<List<Challenge>> cmb = new ArrayList<>(1);
                cmb.add(cr);
                auth.setCombinations(cmb);
            }
        }
    }

    @Override
    public void triggerChallenge(Account account, Challenge challenge) throws AcmeException {
        LOG.debug("triggerChallenge");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("challenge");
            challenge.marshall(claims);

            conn.sendSignedRequest(challenge.getUri(), claims, session, account);

            challenge.unmarshall(conn.readJsonResponse());
        }
    }

    @Override
    public void updateChallenge(Account account, Challenge challenge) throws AcmeException {
        LOG.debug("updateChallenge");
        try (Connection conn = createConnection()) {
            conn.sendRequest(challenge.getUri());
            challenge.unmarshall(conn.readJsonResponse());
        }
    }

    @Override
    public URI requestCertificate(Account account, byte[] csr) throws AcmeException {
        LOG.debug("requestCertificate");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_CERT);
            claims.putBase64("csr", csr);

            conn.sendSignedRequest(resourceUri(Resource.NEW_CERT), claims, session, account);

            // Optionally returns the certificate. Currently it is just ignored.
            // X509Certificate cert = conn.readCertificate();

            return conn.getLocation();
        }
    }

    @Override
    public X509Certificate downloadCertificate(URI certUri) throws AcmeException {
        LOG.debug("downloadCertificate");
        try (Connection conn = createConnection()) {
            conn.sendRequest(certUri);
            return conn.readCertificate();
        }
    }

}
