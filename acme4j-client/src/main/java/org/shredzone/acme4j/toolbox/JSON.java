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
package org.shredzone.acme4j.toolbox;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * A model containing a JSON result. The content is immutable.
 */
public final class JSON implements Serializable {
    private static final long serialVersionUID = 418332625174149030L;

    private static final JSON EMPTY_JSON = new JSON(new HashMap<>());

    private final String path;
    private final Map<String, Object> data;

    /**
     * Creates a new {@link JSON} root object.
     *
     * @param data
     *            {@link Map} containing the parsed JSON data
     */
    private JSON(Map<String, Object> data) {
        this("", data);
    }

    /**
     * Creates a new {@link JSON} branch object.
     *
     * @param path
     *            Path leading to this branch.
     * @param data
     *            {@link Map} containing the parsed JSON data
     */
    private JSON(String path, Map<String, Object> data) {
        this.path = path;
        this.data = data;
    }

    /**
     * Parses JSON from an {@link InputStream}.
     *
     * @param in
     *            {@link InputStream} to read from. Will be closed after use.
     * @return {@link JSON} of the read content.
     */
    public static JSON parse(InputStream in) throws IOException {
        try (var reader = new BufferedReader(new InputStreamReader(in, UTF_8))) {
            var json = reader.lines().map(String::trim).collect(joining());
            return parse(json);
        }
    }

    /**
     * Parses JSON from a String.
     *
     * @param json
     *            JSON string
     * @return {@link JSON} of the read content.
     */
    public static JSON parse(String json) {
        try {
            return new JSON(JsonUtil.parseJson(json));
        } catch (JoseException ex) {
            throw new AcmeProtocolException("Bad JSON: " + json, ex);
        }
    }

    /**
     * Creates a JSON object from a map.
     * <p>
     * The map's content is deeply copied. Changes to the map won't reflect in the created
     * JSON structure.
     *
     * @param data
     *         Map structure
     * @return {@link JSON} of the map's content.
     * @since 3.2.0
     */
    public static JSON fromMap(Map<String, Object> data) {
        return JSON.parse(JsonUtil.toJson(data));
    }

    /**
     * Returns a {@link JSON} of an empty document.
     *
     * @return Empty {@link JSON}
     */
    public static JSON empty() {
        return EMPTY_JSON;
    }

    /**
     * Returns a set of all keys of this object.
     *
     * @return {@link Set} of keys
     */
    public Set<String> keySet() {
        return Collections.unmodifiableSet(data.keySet());
    }

    /**
     * Checks if this object contains the given key.
     *
     * @param key
     *            Name of the key to check
     * @return {@code true} if the key is present
     */
    public boolean contains(String key) {
        return data.containsKey(key);
    }

    /**
     * Returns the {@link Value} of the given key.
     *
     * @param key
     *            Key to read
     * @return {@link Value} of the key
     */
    public Value get(String key) {
        return new Value(
                path.isEmpty() ? key : path + '.' + key,
                data.get(key));
    }

    /**
     * Returns the {@link Value} of the given key.
     *
     * @param key
     *         Key to read
     * @return {@link Value} of the key
     * @throws AcmeNotSupportedException
     *         if the key is not present. The key is used as feature name.
     */
    public Value getFeature(String key) {
        return new Value(
                path.isEmpty() ? key : path + '.' + key,
                data.get(key)).onFeature(key);
    }

    /**
     * Returns the content as JSON string.
     */
    @Override
    public String toString() {
        return JsonUtil.toJson(data);
    }

    /**
     * Returns the content as unmodifiable Map.
     *
     * @since 2.8
     */
    public Map<String,Object> toMap() {
        return Collections.unmodifiableMap(data);
    }

    /**
     * Represents a JSON array.
     */
    public static final class Array implements Iterable<Value> {
        private final String path;
        private final List<Object> data;

        /**
         * Creates a new {@link Array} object.
         *
         * @param path
         *            JSON path to this array.
         * @param data
         *            Array data
         */
        private Array(String path, List<Object> data) {
            this.path = path;
            this.data = data;
        }

        /**
         * Returns the array size.
         *
         * @return Size of the array
         */
        public int size() {
            return data.size();
        }

        /**
         * Returns {@code true} if the array is empty.
         */
        public boolean isEmpty() {
            return data.isEmpty();
        }

        /**
         * Gets the {@link Value} at the given index.
         *
         * @param index
         *            Array index to read from
         * @return {@link Value} at this index
         */
        public Value get(int index) {
            return new Value(path + '[' + index + ']', data.get(index));
        }

        /**
         * Returns a stream of values.
         *
         * @return {@link Stream} of all {@link Value} of this array
         */
        public Stream<Value> stream() {
            return StreamSupport.stream(spliterator(), false);
        }

        /**
         * Creates a new {@link Iterator} that iterates over the array {@link Value}.
         */
        @Override
        public Iterator<Value> iterator() {
            return new ValueIterator(this);
        }
    }

    /**
     * A single JSON value. This instance also covers {@code null} values.
     * <p>
     * All return values are never {@code null} unless specified otherwise. For optional
     * parameters, use {@link Value#optional()}.
     */
    public static final class Value {
        private final String path;
        private final @Nullable Object val;

        /**
         * Creates a new {@link Value}.
         *
         * @param path
         *            JSON path to this value
         * @param val
         *            Value, may be {@code null}
         */
        private Value(String path, @Nullable Object val) {
            this.path = path;
            this.val = val;
        }

        /**
         * Checks if this value is {@code null}.
         *
         * @return {@code true} if this value is present, {@code false} if {@code null}.
         */
        public boolean isPresent() {
            return val != null;
        }

        /**
         * Returns this value as {@link Optional}, for further mapping and filtering.
         *
         * @return {@link Optional} of this value, or {@link Optional#empty()} if this
         *         value is {@code null}.
         * @see #map(Function)
         */
        public Optional<Value> optional() {
            return val != null ? Optional.of(this) : Optional.empty();
        }

        /**
         * Returns this value. If the value was {@code null}, an
         * {@link AcmeNotSupportedException} is thrown. This method is used for mandatory
         * fields that are only present if a certain feature is supported by the server.
         *
         * @param feature
         *         Feature name
         * @return itself
         */
        public Value onFeature(String feature) {
            if (val == null) {
                throw new AcmeNotSupportedException(feature);
            }
            return this;
        }

        /**
         * Returns this value as an {@link Optional} of the desired type, for further
         * mapping and filtering.
         *
         * @param mapper
         *            A {@link Function} that converts a {@link Value} to the desired type
         * @return {@link Optional} of this value, or {@link Optional#empty()} if this
         *         value is {@code null}.
         * @see #optional()
         */
        public <T> Optional<T> map(Function <Value, T> mapper) {
            return optional().map(mapper);
        }

        /**
         * Returns the value as {@link String}.
         */
        public String asString() {
            return required().toString();
        }

        /**
         * Returns the value as JSON object.
         */
        @SuppressWarnings("unchecked")
        public JSON asObject() {
            return new JSON(path, (Map<String, Object>) required(Map.class));
        }

        /**
         * Returns the value as JSON object that was Base64 URL encoded.
         *
         * @since 2.8
         */
        public JSON asEncodedObject() {
            try {
                var raw = AcmeUtils.base64UrlDecode(asString());
                return new JSON(path, JsonUtil.parseJson(new String(raw, UTF_8)));
            } catch (IllegalArgumentException | JoseException ex) {
                throw new AcmeProtocolException(path + ": expected an encoded object", ex);
            }
        }

        /**
         * Returns the value as {@link Problem}.
         *
         * @param baseUrl
         *            Base {@link URL} to resolve relative links against
         */
        public Problem asProblem(URL baseUrl) {
            return new Problem(asObject(), baseUrl);
        }

        /**
         * Returns the value as {@link Identifier}.
         *
         * @since 2.3
         */
        public Identifier asIdentifier() {
            return new Identifier(asObject());
        }

        /**
         * Returns the value as {@link JSON.Array}.
         * <p>
         * Unlike the other getters, this method returns an empty array if the value is
         * not set. Use {@link #isPresent()} to find out if the value was actually set.
         */
        @SuppressWarnings("unchecked")
        public Array asArray() {
            if (val == null) {
                return new Array(path, Collections.emptyList());
            }

            try {
                return new Array(path, (List<Object>) val);
            } catch (ClassCastException ex) {
                throw new AcmeProtocolException(path + ": expected an array", ex);
            }
        }

        /**
         * Returns the value as int.
         */
        public int asInt() {
            return (required(Number.class)).intValue();
        }

        /**
         * Returns the value as boolean.
         */
        public boolean asBoolean() {
            return required(Boolean.class);
        }

        /**
         * Returns the value as {@link URI}.
         */
        public URI asURI() {
            try {
                return new URI(asString());
            } catch (URISyntaxException ex) {
                throw new AcmeProtocolException(path + ": bad URI " + val, ex);
            }
        }

        /**
         * Returns the value as {@link URL}.
         */
        public URL asURL() {
            try {
                return new URL(asString());
            } catch (MalformedURLException ex) {
                throw new AcmeProtocolException(path + ": bad URL " + val, ex);
            }
        }

        /**
         * Returns the value as {@link Instant}.
         */
        public Instant asInstant() {
            try {
                return parseTimestamp(asString());
            } catch (IllegalArgumentException ex) {
                throw new AcmeProtocolException(path + ": bad date " + val, ex);
            }
        }

        /**
         * Returns the value as {@link Duration}.
         *
         * @since 2.3
         */
        public Duration asDuration() {
            return Duration.ofSeconds(required(Number.class).longValue());
        }

        /**
         * Returns the value as base64 decoded byte array.
         */
        public byte[] asBinary() {
            return AcmeUtils.base64UrlDecode(asString());
        }

        /**
         * Returns the parsed {@link Status}.
         */
        public Status asStatus() {
            return Status.parse(asString());
        }

        /**
         * Checks if the value is present. An {@link AcmeProtocolException} is thrown if
         * the value is {@code null}.
         *
         * @return val that is guaranteed to be non-{@code null}
         */
        private Object required() {
            if (val == null) {
                throw new AcmeProtocolException(path + ": required, but not set");
            }
            return val;
        }

        /**
         * Checks if the value is present. An {@link AcmeProtocolException} is thrown if
         * the value is {@code null} or is not of the expected type.
         *
         * @param type
         *         expected type
         * @return val that is guaranteed to be non-{@code null}
         */
        private <T> T required(Class<T> type) {
            if (val == null) {
                throw new AcmeProtocolException(path + ": required, but not set");
            }
            if (!type.isInstance(val)) {
                throw new AcmeProtocolException(path + ": cannot convert to " + type.getSimpleName());
            }
            return type.cast(val);
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof Value)) {
                return false;
            }
            return Objects.equals(val, ((Value) obj).val);
        }

        @Override
        public int hashCode() {
            return val != null ? val.hashCode() : 0;
        }
    }

    /**
     * An {@link Iterator} over array {@link Value}.
     */
    private static class ValueIterator implements Iterator<Value> {
        private final Array array;
        private int index = 0;

        public ValueIterator(Array array) {
            this.array = array;
        }

        @Override
        public boolean hasNext() {
            return index < array.size();
        }

        @Override
        public Value next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            return array.get(index++);
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

}
