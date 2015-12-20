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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * A generic implementation of {@link Challenge}. It can be used as a base class for
 * actual challenge implemenation, but it is also used if the ACME server offers a
 * proprietary challenge that is unknown to acme4j.
 *
 * @author Richard "Shred" Körber
 */
public class GenericChallenge implements Challenge {
    private static final long serialVersionUID = 2338794776848388099L;

    protected static final String KEY_TYPE = "type";
    protected static final String KEY_STATUS = "status";
    protected static final String KEY_URI = "uri";
    protected static final String KEY_VALIDATED = "validated";
    protected static final String KEY_TOKEN = "token";
    protected static final String KEY_KEY_AUTHORIZSATION = "keyAuthorization";

    private transient Map<String, Object> data = new HashMap<>();

    @Override
    public String getType() {
        return get(KEY_TYPE);
    }

    @Override
    public Status getStatus() {
        String status = get(KEY_STATUS);
        return (status != null ? Status.valueOf(status.toUpperCase()) : Status.PENDING);
    }

    @Override
    public URI getLocation() {
        String uri = get(KEY_URI);
        if (uri == null) {
            return null;
        }

        try {
            return new URI(uri);
        } catch (URISyntaxException ex) {
            throw new IllegalStateException("Invalid URI", ex);
        }
    }

    @Override
    public String getValidated() {
        return get(KEY_VALIDATED);
    }

    @Override
    public void authorize(Account account) {
        if (account == null) {
            throw new NullPointerException("account must not be null");
        }
    }

    @Override
    public void unmarshall(Map<String, Object> map) {
        String type = map.get(KEY_TYPE).toString();
        if (type == null) {
            throw new IllegalArgumentException("map does not contain a type");
        }
        if (!acceptable(type)) {
            throw new IllegalArgumentException("wrong type: " + type);
        }

        data.clear();
        data.putAll(map);
    }

    @Override
    public void marshall(ClaimBuilder cb) {
        cb.putAll(data);
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
     * Puts a value to the challenge state.
     *
     * @param key
     *            Key
     * @param value
     *            Value, may be {@code null}
     */
    protected void put(String key, Object value) {
        data.put(key, value);
    }

    /**
     * Computes a JWK Thumbprint. It is frequently used in responses.
     *
     * @param key
     *            {@link PublicKey} to create a thumbprint of
     * @return Thumbprint, SHA-256 hashed
     * @see <a href="https://tools.ietf.org/html/rfc7638">RFC 7638</a>
     */
    public static byte[] jwkThumbprint(PublicKey key) {
        if (key == null) {
            throw new NullPointerException("key must not be null");
        }

        try {
            final JsonWebKey jwk = JsonWebKey.Factory.newJwk(key);

            // We need to use ClaimBuilder to bring the keys in lexicographical order.
            ClaimBuilder cb = new ClaimBuilder();
            cb.putAll(jwk.toParams(OutputControlLevel.PUBLIC_ONLY));

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(cb.toString().getBytes("UTF-8"));
            return md.digest();
        } catch (JoseException | NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new IllegalArgumentException("Cannot compute key thumbprint", ex);
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
            throw new IOException("Cannot deserialize", ex);
        }
    }

}
