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
package org.shredzone.acme4j.challenge;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.AcmeResource;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TimestampParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A generic challenge. It can be used as a base class for actual challenge
 * implementations, but it is also used if the ACME server offers a proprietary challenge
 * that is unknown to acme4j.
 * <p>
 * Subclasses must override {@link Challenge#acceptable(String)} so it only accepts the
 * own type. {@link Challenge#respond(ClaimBuilder)} should be overridden to put all
 * required data to the response.
 */
public class Challenge extends AcmeResource {
    private static final long serialVersionUID = 2338794776848388099L;
    private static final Logger LOG = LoggerFactory.getLogger(Challenge.class);

    protected static final String KEY_TYPE = "type";
    protected static final String KEY_STATUS = "status";
    protected static final String KEY_URI = "uri";
    protected static final String KEY_VALIDATED = "validated";

    private transient Map<String, Object> data = new HashMap<>();

    /**
     * Returns a {@link Challenge} object of an existing challenge.
     *
     * @param session
     *            {@link Session} to be used
     * @param location
     *            Challenge location
     * @return {@link Challenge}
     */
    @SuppressWarnings("unchecked")
    public static <T extends Challenge> T bind(Session session, URI location) throws AcmeException {
        if (session == null) {
            throw new NullPointerException("session must not be null");
        }
        if (location == null) {
            throw new NullPointerException("location must not be null");
        }

        LOG.debug("bind");
        try (Connection conn = session.provider().connect()) {
            int rc = conn.sendRequest(location);
            if (rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            Map<String, Object> json = conn.readJsonResponse();
            if (!(json.containsKey("type"))) {
                throw new IllegalArgumentException("Provided URI is not a challenge URI");
            }

            return (T) session.createChallenge(json);
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Creates a new generic {@link Challenge} object.
     *
     * @param session
     *            {@link Session} to bind to.
     */
    public Challenge(Session session) {
        super(session);
    }

    /**
     * Returns the challenge type by name (e.g. "http-01").
     */
    public String getType() {
        return get(KEY_TYPE);
    }

    /**
     * Returns the current status of the challenge.
     */
    public Status getStatus() {
        return Status.parse((String) get(KEY_STATUS), Status.PENDING);
    }

    /**
     * Returns the location {@link URI} of the challenge.
     */
    @Override
    public URI getLocation() {
        String uri = get(KEY_URI);
        if (uri == null) {
            return null;
        }

        return URI.create(uri);
    }

    /**
     * Returns the validation date, if returned by the server.
     */
    public Date getValidated() {
        String valStr = get(KEY_VALIDATED);
        if (valStr != null) {
            return TimestampParser.parse(valStr);
        } else {
            return null;
        }
    }

    /**
     * Exports the response state, as preparation for triggering the challenge.
     *
     * @param cb
     *            {@link ClaimBuilder} to copy the response to
     */
    protected void respond(ClaimBuilder cb) {
        cb.put(KEY_TYPE, getType());
    }

    /**
     * Checks if the type is acceptable to this challenge.
     *
     * @param type
     *            Type to check
     * @return {@code true} if acceptable, {@code false} if not
     */
    protected boolean acceptable(String type) {
        return true;
    }

    /**
     * Sets the challenge state to the given JSON map.
     *
     * @param map
     *            JSON map containing the challenge data
     */
    public void unmarshall(Map<String, Object> map) {
        String type = map.get(KEY_TYPE).toString();
        if (type == null) {
            throw new IllegalArgumentException("map does not contain a type");
        }
        if (!acceptable(type)) {
            throw new AcmeProtocolException("wrong type: " + type);
        }

        data.clear();
        data.putAll(map);
        authorize();
    }

    /**
     * Gets a value from the challenge state.
     *
     * @param key
     *            Key
     * @return Value, or {@code null} if not set
     */
    @SuppressWarnings("unchecked")
    protected <T> T get(String key) {
        return (T) data.get(key);
    }

    /**
     * Callback that is invoked when the challenge is supposed to compute its
     * authorization data.
     */
    protected void authorize() {
        // Does nothing here...
    }

    /**
     * Triggers this {@link Challenge}. The ACME server is requested to validate the
     * response. Note that the validation is performed asynchronously by the ACME server.
     */
    public void trigger() throws AcmeException {
        LOG.debug("trigger");
        try (Connection conn = getSession().provider().connect()) {
            ClaimBuilder claims = new ClaimBuilder();
            claims.putResource("challenge");
            respond(claims);

            int rc = conn.sendSignedRequest(getLocation(), claims, getSession());
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            unmarshall(conn.readJsonResponse());
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Updates the state of this challenge.
     *
     * @throws AcmeRetryAfterException
     *             the challenge is still being validated, and the server returned an
     *             estimated date when the challenge will be completed. If you are polling
     *             for the challenge to complete, you should wait for the date given in
     *             {@link AcmeRetryAfterException#getRetryAfter()}. Note that the
     *             challenge status is updated even if this exception was thrown.
     */
    public void update() throws AcmeException {
        LOG.debug("update");
        try (Connection conn = getSession().provider().connect()) {
            int rc = conn.sendRequest(getLocation());
            if (rc != HttpURLConnection.HTTP_OK && rc != HttpURLConnection.HTTP_ACCEPTED) {
                conn.throwAcmeException();
            }

            unmarshall(conn.readJsonResponse());

            if (rc == HttpURLConnection.HTTP_ACCEPTED) {
                Date retryAfter = conn.getRetryAfterHeader();
                if (retryAfter != null) {
                    throw new AcmeRetryAfterException("challenge is not completed yet",
                                    retryAfter);
                }
            }
        } catch (IOException ex) {
            throw new AcmeNetworkException(ex);
        }
    }

    /**
     * Serialize the data map in JSON.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeUTF(JsonUtil.toJson(data));
        out.defaultWriteObject();
    }

    /**
     * Deserialize the JSON representation of the data map.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            data = new HashMap<>(JsonUtil.parseJson(in.readUTF()));
            in.defaultReadObject();
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Cannot deserialize", ex);
        }
    }

}
