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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.SignatureUtils;
import org.shredzone.acme4j.util.TimestampParser;
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
     * @param data
     *            Challenge JSON data
     * @return {@link Challenge} instance
     */
    protected abstract Challenge createChallenge(Map<String, Object> data);

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
    public void newRegistration(Registration registration) throws AcmeException {
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

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_REG), claims, session, registration);
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
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void modifyRegistration(Registration registration) throws AcmeException {
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

            int rc = conn.sendSignedRequest(registration.getLocation(), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            URI location = conn.getLocation();
            if (location != null) {
                registration.setLocation(conn.getLocation());
            }

            URI tos = conn.getLink("terms-of-service");
            if (tos != null) {
                registration.setAgreement(tos);
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void changeRegistrationKey(Registration registration, KeyPair newKeyPair) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (registration.getLocation() == null) {
            throw new IllegalArgumentException("registration location must not be null. Use newRegistration() if not known.");
        }
        if (newKeyPair == null) {
            throw new NullPointerException("newKeyPair must not be null");
        }
        if (Arrays.equals(registration.getKeyPair().getPrivate().getEncoded(),
                        newKeyPair.getPrivate().getEncoded())) {
            throw new IllegalArgumentException("newKeyPair must actually be a new key pair");
        }

        String newKey;
        try {
            ClaimBuilder oldKeyClaim = new ClaimBuilder();
            oldKeyClaim.putResource("reg");
            oldKeyClaim.putKey("oldKey", registration.getKeyPair().getPublic());

            final PublicJsonWebKey newKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(newKeyPair.getPublic());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(oldKeyClaim.toString());
            jws.getHeaders().setJwkHeaderValue("jwk", newKeyJwk);
            jws.setAlgorithmHeaderValue(SignatureUtils.keyAlgorithm(newKeyJwk));
            jws.setKey(newKeyPair.getPrivate());
            jws.sign();

            newKey = jws.getCompactSerialization();
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Bad newKeyPair", ex);
        }

        LOG.debug("changeRegistrationKey");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            claims.put("newKey", newKey);

            int rc = conn.sendSignedRequest(registration.getLocation(), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void recoverRegistration(Registration registration) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (registration.getLocation() == null) {
            throw new IllegalArgumentException("registration location must not be null");
        }

        LOG.debug("recoverRegistration");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.RECOVER_REG);
            claims.put("method", "contact");
            claims.put("base", registration.getLocation());
            if (!registration.getContacts().isEmpty()) {
                claims.put("contact", registration.getContacts());
            }

            int rc = conn.sendSignedRequest(resourceUri(Resource.RECOVER_REG), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_CREATED) {
                conn.throwAcmeException();
            }

            registration.setLocation(conn.getLocation());

            URI tos = conn.getLink("terms-of-service");
            if (tos != null) {
                registration.setAgreement(tos);
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void deleteRegistration(Registration registration) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (registration.getLocation() == null) {
            throw new IllegalArgumentException("registration location must not be null");
        }

        LOG.debug("deleteRegistration");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("reg");
            claims.put("delete", true);

            int rc = conn.sendSignedRequest(registration.getLocation(), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void newAuthorization(Registration registration, Authorization auth) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
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

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_AUTHZ), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_CREATED) {
                conn.throwAcmeException();
            }

            auth.setLocation(conn.getLocation());

            Map<String, Object> result = conn.readJsonResponse();
            unmarshalAuthorization(result, auth);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void updateAuthorization(Authorization auth) throws AcmeException {
        if (auth == null) {
            throw new NullPointerException("auth must not be null");
        }
        if (auth.getLocation() == null) {
            throw new IllegalArgumentException("auth location must not be null. Use newAuthorization() if not known.");
        }

        LOG.debug("updateAuthorization");
        try (Connection conn = createConnection()) {
            int rc = conn.sendRequest(auth.getLocation());
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            // HTTP_ACCEPTED requires Retry-After header to be set

            Map<String, Object> result = conn.readJsonResponse();
            unmarshalAuthorization(result, auth);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void deleteAuthorization(Registration registration, Authorization auth) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (auth == null) {
            throw new NullPointerException("auth must not be null");
        }
        if (auth.getLocation() == null) {
            throw new IllegalArgumentException("auth location must not be null. Use newAuthorization() if not known.");
        }

        LOG.debug("deleteAuthorization");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("authz");
            claims.put("delete", true);

            int rc = conn.sendSignedRequest(auth.getLocation(), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void triggerChallenge(Registration registration, Challenge challenge) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
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
            challenge.respond(claims);

            int rc = conn.sendSignedRequest(challenge.getLocation(), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            challenge.unmarshall(conn.readJsonResponse());
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
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
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
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
                throw new IllegalArgumentException("Provided URI is not a challenge URI");
            }

            return (T) createChallenge(json);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public URI requestCertificate(Registration registration, byte[] csr) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (csr == null) {
            throw new NullPointerException("csr must not be null");
        }

        LOG.debug("requestCertificate");
        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.NEW_CERT);
            claims.putBase64("csr", csr);

            int rc = conn.sendSignedRequest(resourceUri(Resource.NEW_CERT), claims, session, registration);
            if (rc != HttpURLConnection.HTTP_CREATED && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            // HTTP_ACCEPTED requires Retry-After header to be set

            // Optionally returns the certificate. Currently it is just ignored.
            // X509Certificate cert = conn.readCertificate();

            return conn.getLocation();
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
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
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    @Override
    public void revokeCertificate(Registration registration, X509Certificate certificate) throws AcmeException {
        if (registration == null) {
            throw new NullPointerException("registration must not be null");
        }
        if (certificate == null) {
            throw new NullPointerException("certificate must not be null");
        }

        LOG.debug("revokeCertificate");
        URI resUri = resourceUri(Resource.REVOKE_CERT);
        if (resUri == null) {
            throw new AcmeProtocolException("CA does not support certificate revocation");
        }

        try (Connection conn = createConnection()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource(Resource.REVOKE_CERT);
            claims.putBase64("certificate", certificate.getEncoded());

            int rc = conn.sendSignedRequest(resUri, claims, session, registration);
            if (rc != HttpURLConnection.HTTP_OK) {
                conn.throwAcmeException();
            }
        } catch (CertificateEncodingException ex) {
            throw new AcmeProtocolException("Invalid certificate", ex);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Sets {@link Authorization} properties according to the given JSON data.
     *
     * @param json
     *            JSON data
     * @param auth
     *            {@link Authorization} to update
     */
    @SuppressWarnings("unchecked")
    private void unmarshalAuthorization(Map<String, Object> json, Authorization auth) {
        auth.setStatus(Status.parse((String) json.get("status"), Status.PENDING));

        String expires = (String) json.get("expires");
        if (expires != null) {
            auth.setExpires(TimestampParser.parse(expires));
        }

        Map<String, Object> identifier = (Map<String, Object>) json.get("identifier");
        if (identifier != null) {
            auth.setDomain((String) identifier.get("value"));
        }

        Collection<Map<String, Object>> challenges =
                        (Collection<Map<String, Object>>) json.get("challenges");
        List<Challenge> cr = new ArrayList<>();
        for (Map<String, Object> c : challenges) {
            Challenge ch = createChallenge(c);
            if (ch != null) {
                cr.add(ch);
            }
        }
        auth.setChallenges(cr);

        Collection<List<Number>> combinations =
                        (Collection<List<Number>>) json.get("combinations");
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
