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
package org.shredzone.acme4j.toolbox;

import static org.shredzone.acme4j.toolbox.AcmeUtils.base64UrlEncode;

import java.security.Key;
import java.security.PublicKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Builder for JSON structures.
 * <p>
 * Example:
 * <pre>
 * JSONBuilder cb = new JSONBuilder();
 * cb.put("foo", 123).put("bar", "hello world");
 * cb.object("sub").put("data", "subdata");
 * cb.array("array", 123, 456, 789);
 * </pre>
 */
@ParametersAreNonnullByDefault
public class JSONBuilder {

    private final Map<String, Object> data = new LinkedHashMap<>();

    /**
     * Puts a property. If a property with the key exists, it will be replaced.
     *
     * @param key
     *            Property key
     * @param value
     *            Property value
     * @return {@code this}
     */
    public JSONBuilder put(String key, @Nullable Object value) {
        data.put(Objects.requireNonNull(key, "key"), value);
        return this;
    }

    /**
     * Puts an {@link Instant} to the JSON. If a property with the key exists, it will be
     * replaced.
     *
     * @param key
     *            Property key
     * @param value
     *            Property {@link Instant} value
     * @return {@code this}
     */
    public JSONBuilder put(String key, @Nullable Instant value) {
        if (value == null) {
            put(key, (Object) null);
            return this;
        }

        put(key, DateTimeFormatter.ISO_INSTANT.format(value));
        return this;
    }

    /**
     * Puts binary data to the JSON. The data is base64 url encoded.
     *
     * @param key
     *            Property key
     * @param data
     *            Property data
     * @return {@code this}
     */
    public JSONBuilder putBase64(String key, byte[] data) {
        return put(key, base64UrlEncode(data));
    }

    /**
     * Puts a {@link Key} into the claim. The key is serializied as JWK.
     *
     * @param key
     *            Property key
     * @param publickey
     *            {@link PublicKey} to serialize
     * @return {@code this}
     */
    public JSONBuilder putKey(String key, PublicKey publickey) {
        Objects.requireNonNull(publickey, "publickey");

        try {
            final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(publickey);
            Map<String, Object> jwkParams = jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
            object(key).data.putAll(jwkParams);
            return this;
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Invalid key", ex);
        }
    }

    /**
     * Creates an object for the given key.
     *
     * @param key
     *            Key of the object
     * @return Newly created {@link JSONBuilder} for the object.
     */
    public JSONBuilder object(String key) {
        JSONBuilder subBuilder = new JSONBuilder();
        data.put(key, subBuilder.data);
        return subBuilder;
    }

    /**
     * Puts an array.
     *
     * @param key
     *            Property key
     * @param values
     *            Collection of property values
     * @return {@code this}
     */
    public JSONBuilder array(String key, Collection<?> values) {
        data.put(key, values);
        return this;
    }

    /**
     * Returns a {@link Map} representation of the current state.
     *
     * @return {@link Map} of the current state
     */
    public Map<String, Object> toMap() {
        return Collections.unmodifiableMap(data);
    }

    /**
     * Returns a {@link JSON} representation of the current state.
     *
     * @return {@link JSON} of the current state
     */
    public JSON toJSON() {
        return JSON.parse(toString());
    }

    /**
     * Returns a JSON string representation of the current state.
     */
    @Override
    public String toString() {
        return JsonUtil.toJson(data);
    }

}
