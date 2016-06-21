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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TimestampParser;

/**
 * A generic implementation of {@link Challenge}. It can be used as a base class for
 * actual challenge implemenation, but it is also used if the ACME server offers a
 * proprietary challenge that is unknown to acme4j.
 * <p>
 * Subclasses must override {@link GenericChallenge#acceptable(String)} so it only
 * accepts the own type. {@link GenericChallenge#respond(ClaimBuilder)} should be
 * overridden to put all required data to the response.
 *
 * @author Richard "Shred" Körber
 */
public class GenericChallenge implements Challenge {
    private static final long serialVersionUID = 2338794776848388099L;

    protected static final String KEY_TYPE = "type";
    protected static final String KEY_STATUS = "status";
    protected static final String KEY_URI = "uri";
    protected static final String KEY_VALIDATED = "validated";

    private transient Map<String, Object> data = new HashMap<>();

    @Override
    public String getType() {
        return get(KEY_TYPE);
    }

    @Override
    public Status getStatus() {
        return Status.parse((String) get(KEY_STATUS), Status.PENDING);
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
            throw new AcmeProtocolException("Invalid URI", ex);
        }
    }

    @Override
    public Date getValidated() {
        String valStr = get(KEY_VALIDATED);
        if (valStr != null) {
            return TimestampParser.parse(valStr);
        } else {
            return null;
        }
    }

    @Override
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
    }

    @Override
    public void respond(ClaimBuilder cb) {
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
