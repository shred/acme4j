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
package org.shredzone.acme4j.util;

import java.security.Key;
import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.connector.Resource;

/**
 * Builder for claim structures.
 * <p>
 * Example:
 * <pre>
 * ClaimBuilder cb = new ClaimBuilder();
 * cb.put("foo", 123).put("bar", "hello world");
 * cb.object("sub").put("data", "subdata");
 * cb.array("array", 123, 456, 789);
 * </pre>
 *
 * @author Richard "Shred" Körber
 */
public class ClaimBuilder {

    private final Map<String, Object> data = new TreeMap<>();

    /**
     * Puts a claim. If a claim with the key exists, it will be replaced.
     *
     * @param key
     *            Claim key
     * @param value
     *            Claim value
     * @return {@code this}
     */
    public ClaimBuilder put(String key, Object value) {
        if (key == null) {
            throw new NullPointerException("key must not be null");
        }

        data.put(key, value);
        return this;
    }

    /**
     * Puts a resource claim.
     *
     * @param resource
     *            Resource name
     * @return {@code this}
     */
    public ClaimBuilder putResource(String resource) {
        return put("resource", resource);
    }

    /**
     * Puts a resource claim.
     *
     * @param resource
     *            {@link Resource}
     * @return {@code this}
     */
    public ClaimBuilder putResource(Resource resource) {
        return putResource(resource.path());
    }

    /**
     * Puts an entire map into the claim.
     *
     * @param map
     *            Map to put
     * @return {@code this}
     */
    public ClaimBuilder putAll(Map<String, Object> map) {
        data.putAll(map);
        return this;
    }

    /**
     * Puts binary data to the claim. The data is base64 url encoded.
     *
     * @param key
     *            Claim key
     * @param data
     *            Claim data
     * @return {@code this}
     */
    public ClaimBuilder putBase64(String key, byte[] data) {
        return put(key, Base64Url.encode(data));
    }

    /**
     * Puts a {@link Key} into the claim. The key is serializied as JWK.
     *
     * @param key
     *            Claim key
     * @param publickey
     *            {@link PublicKey} to serialize
     * @return {@code this}
     */
    public ClaimBuilder putKey(String key, PublicKey publickey) {
        if (publickey == null) {
            throw new NullPointerException("publickey must not be null");
        }

        try {
            final JsonWebKey jwk = JsonWebKey.Factory.newJwk(publickey);
            Map<String, Object> jwkParams = jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
            object(key).putAll(jwkParams);
            return this;
        } catch (JoseException ex) {
            throw new IllegalArgumentException("Invalid key", ex);
        }
    }

    /**
     * Creates a sub-claim for the given key.
     *
     * @param key
     *            Key of the sub-claim
     * @return Newly created {@link ClaimBuilder} for the sub-claim.
     */
    public ClaimBuilder object(String key) {
        ClaimBuilder subBuilder = new ClaimBuilder();
        data.put(key, subBuilder.data);
        return subBuilder;
    }

    /**
     * Puts an array claim.
     *
     * @param key
     *            Claim key
     * @param values
     *            Array of claim values
     * @return {@code this}
     */
    public ClaimBuilder array(String key, Object... values) {
        data.put(key, values);
        return this;
    }

    /**
     * Returns a JSON representation of the claims.
     */
    @Override
    public String toString() {
        return JsonUtil.toJson(data);
    }

}
