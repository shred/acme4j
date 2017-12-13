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

import static java.util.stream.Collectors.joining;
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * A model containing a JSON result. The content is immutable.
 */
@SuppressWarnings("unchecked")
public final class JSON implements Serializable {
    private static final long serialVersionUID = 3091273044605709204L;

    private static final JSON EMPTY_JSON = new JSON(new HashMap<String, Object>());

    private final String path;
    private Map<String, Object> data;

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
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, "utf-8"))) {
            String json = reader.lines().map(String::trim).collect(joining());
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
     * Returns the content as JSON string.
     */
    @Override
    public String toString() {
        return JsonUtil.toJson(data);
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
     */
    public static final class Value {
        private final String path;
        private final Object val;

        /**
         * Creates a new {@link Value}.
         *
         * @param path
         *            JSON path to this value
         * @param val
         *            Value, may be {@code null}
         */
        private Value(String path, Object val) {
            this.path = path;
            this.val = val;
        }

        /**
         * Checks if the value is present. An {@link AcmeProtocolException} is thrown if
         * the value is {@code null}.
         *
         * @return itself
         */
        public Value required() {
            if (val == null) {
                throw new AcmeProtocolException(path + ": required, but not set");
            }
            return this;
        }

        /**
         * Checks if the value is present. If not, the default value is used instead.
         *
         * @param def Default value
         * @return itself
         */
        public Value orElse(Object def) {
            return val != null ? this : new Value(path, def);
        }

        /**
         * Returns the value as {@link String}.
         *
         * @return {@link String}, or {@code null} if the value was not set.
         */
        public String asString() {
            return val != null ? val.toString() : null;
        }

        /**
         * Returns the value as JSON object.
         *
         * @return {@link JSON}, or {@code null} if the value was not set.
         */
        public JSON asObject() {
            if (val == null) {
                return null;
            }

            try {
                return new JSON(path, (Map<String, Object>) val);
            } catch (ClassCastException ex) {
                throw new AcmeProtocolException(path + ": expected an object", ex);
            }
        }

        /**
         * Returns the value as {@link Problem}.
         *
         * @param baseUrl
         *            Base {@link URL} to resolve relative links against
         * @return {@link Problem}, or {@code null} if the value was not set.
         */
        public Problem asProblem(URL baseUrl) {
            if (val == null) {
                return null;
            }

            return new Problem(asObject(), baseUrl);
        }

        /**
         * Returns the value as JSON array.
         *
         * @return {@link JSON.Array}, which is empty if the value was not set.
         */
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
         *
         * @return integer value
         */
        public int asInt() {
            required();

            try {
                return ((Number) val).intValue();
            } catch (ClassCastException ex) {
                throw new AcmeProtocolException(path + ": bad number " + val, ex);
            }
        }

        /**
         * Returns the value as boolean.
         *
         * @return integer value
         */
        public boolean asBoolean() {
            required();

            try {
                return (Boolean) val;
            } catch (ClassCastException ex) {
                throw new AcmeProtocolException(path + ": bad boolean " + val, ex);
            }
        }

        /**
         * Returns the value as {@link URI}.
         *
         * @return {@link URI}, or {@code null} if the value was not set.
         */
        public URI asURI() {
            if (val == null) {
                return null;
            }

            try {
                return new URI(val.toString());
            } catch (URISyntaxException ex) {
                throw new AcmeProtocolException(path + ": bad URI " + val, ex);
            }
        }

        /**
         * Returns the value as {@link URL}.
         *
         * @return {@link URL}, or {@code null} if the value was not set.
         */
        public URL asURL() {
            if (val == null) {
                return null;
            }

            try {
                return new URL(val.toString());
            } catch (MalformedURLException ex) {
                throw new AcmeProtocolException(path + ": bad URL " + val, ex);
            }
        }

        /**
         * Returns the value as {@link Instant}.
         *
         * @return {@link Instant}, or {@code null} if the value was not set.
         */
        public Instant asInstant() {
            if (val == null) {
                return null;
            }

            try {
                return parseTimestamp(val.toString());
            } catch (IllegalArgumentException ex) {
                throw new AcmeProtocolException(path + ": bad date " + val, ex);
            }
        }

        /**
         * Returns the value as base64 decoded byte array.
         *
         * @return byte array, or {@code null} if the value was not set.
         */
        public byte[] asBinary() {
            if (val == null) {
                return null; //NOSONAR: we want to return null here
            }

            return AcmeUtils.base64UrlDecode(val.toString());
        }

        /**
         * Returns the parsed status.
         *
         * @param def
         *            Default status if value is not present or {@code null}
         * @return {@link Status}
         */
        public Status asStatusOrElse(Status def) {
            if (val == null) {
                return def;
            }

            return Status.parse(val.toString());
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null || !(obj instanceof Value)) {
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
