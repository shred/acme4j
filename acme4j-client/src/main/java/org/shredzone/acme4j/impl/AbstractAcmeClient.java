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

import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
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
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
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

    /**
     * Returns the {@link Session} instance of this client.
     */
    protected Session getSession() {
        return session;
    }

    @Override
    public void newRegistration(Account account, Registration registration) throws AcmeException {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (registration.getLocation() != null) {
            throw new IllegalArgumentException("registration location must be null");
        }
        if (registration.getAgreement() != null) {
            throw new IllegalArgumentException("registration agreement must be null");
        }

        LOG.debug("newRegistration");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_REG);
            if (!registration.getContacts().isEmpty()) {
                claims.put("contact", registration.getContacts());
            }

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_REG), claims, session, account);
            if (rc != HttpURLConnection.HTTP_CREATED && rc != HttpURLConnection.HTTP_CONFLICT) {
                conn.throwAcmeException();
            }

            URI location = conn.getLocation();
            if (location != null) {
                registration.setLocation(location);
            }

            URI tos = conn.getLink("terms-of-service");
            if (tos != null) {
                registration.setAgreement(tos);
            }

            if (rc == HttpURLConnection.HTTP_CONFLICT) {
                throw new AcmeConflictException("Account is already registered", location);
            }
        }
    }

    @Override
    public void modifyRegistration(Account account, Registration registration) throws AcmeException {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (registration.getLocation() == null) {
            throw new IllegalArgumentException("registration location must not be null. Use newRegistration() if not known.");
        }

        LOG.debug("modifyRegistration");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            if (!registration.getContacts().isEmpty()) {
                claims.put("contact", registration.getContacts());
            }
            if (registration.getAgreement() != null) {
                claims.put("agreement", registration.getAgreement());
            }

            int rc = conn.sendSignedRequest(registration.getLocation(), claims, session, account);
            if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            registration.setLocation(conn.getLocation());

            URI tos = conn.getLink("terms-of-service");
            if (tos != null) {
                registration.setAgreement(tos);
            }
        }
    }

    @Override
    public void newAuthorization(Account account, Authorization auth) throws AcmeException {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (auth == null) {
            throw new NullPointerException("auth must not be null");
        }
        if (auth.getDomain() == null || auth.getDomain().isEmpty()) {
            throw new IllegalArgumentException("auth domain must not be empty or null");
        }

        LOG.debug("newAuthorization");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_AUTHZ);
            claims.object("identifier")
                    .put("type", "dns")
                    .put("value", auth.getDomain());

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_AUTHZ), claims, session, account);
            if (rc != HttpURLConnection.HTTP_CREATED) {
                conn.throwAcmeException();
            }

            Map<String, Object> result = conn.readJsonResponse();

            auth.setStatus((String) result.get("status"));

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
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (challenge == null) {
            throw new NullPointerException("challenge must not be null");
        }
        if (challenge.getLocation() == null) {
            throw new IllegalArgumentException("challenge location is not set");
        }

        LOG.debug("triggerChallenge");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("challenge");
            challenge.marshall(claims);

            int rc = conn.sendSignedRequest(challenge.getLocation(), claims, session, account);
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            challenge.unmarshall(conn.readJsonResponse());
        }
    }

    @Override
    public void updateChallenge(Challenge challenge) throws AcmeException {
        if (challenge == null) {
            throw new NullPointerException("challenge must not be null");
        }
        if (challenge.getLocation() == null) {
            throw new IllegalArgumentException("challenge location is not set");
        }

        LOG.debug("updateChallenge");
        try (Connection conn = createConnection()) {
            int rc = conn.sendRequest(challenge.getLocation());
            if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            challenge.unmarshall(conn.readJsonResponse());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends Challenge> T restoreChallenge(URI challengeUri) throws AcmeException {
        if (challengeUri == null) {
            throw new NullPointerException("challengeUri must not be null");
        }

        LOG.debug("restoreChallenge");
        try (Connection conn = createConnection()) {
            int rc = conn.sendRequest(challengeUri);
            if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            Map<String, Object> json = conn.readJsonResponse();
            if (!(json.containsKey("type"))) {
                throw new AcmeException("Provided URI is not a challenge URI");
            }

            T challenge = (T) createChallenge(json.get("type").toString());
            challenge.unmarshall(json);
            return challenge;
        }
    }

    @Override
    public URI requestCertificate(Account account, byte[] csr) throws AcmeException {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (csr == null) {
            throw new NullPointerException("csr must not be null");
        }

        LOG.debug("requestCertificate");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_CERT);
            claims.putBase64("csr", csr);

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_CERT), claims, session, account);
            if (rc != HttpURLConnection.HTTP_CREATED && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            // HTTP_ACCEPTED requires Retry-After header to be set

            // Optionally returns the certificate. Currently it is just ignored.
            // X509Certificate cert = conn.readCertificate();

            return conn.getLocation();
        }
    }

    @Override
    public X509Certificate downloadCertificate(URI certUri) throws AcmeException {
        if (certUri == null) {
            throw new NullPointerException("certUri must not be null");
        }

        LOG.debug("downloadCertificate");
        try (Connection conn = createConnection()) {
            int rc = conn.sendRequest(certUri);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }

            return conn.readCertificate();
        }
    }

    @Override
    public void revokeCertificate(Account account, X509Certificate certificate) throws AcmeException {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
        if (certificate == null) {
            throw new NullPointerException("certificate must not be null");
        }

        LOG.debug("revokeCertificate");
        URI resUri = resourceUri(Resource.REVOKE_CERT);
        if (resUri == null) {
            throw new AcmeException("CA does not support certificate revocation");
        }

        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.REVOKE_CERT);
            claims.putBase64("certificate", certificate.getEncoded());

            int rc = conn.sendSignedRequest(resUri, claims, session, account);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (CertificateEncodingException ex) {
            throw new IllegalArgumentException("Invalid certificate", ex);
        }
    }

}
