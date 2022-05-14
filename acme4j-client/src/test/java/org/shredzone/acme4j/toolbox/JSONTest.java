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
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON.Value;

/**
 * Unit test for {@link JSON}.
 */
public class JSONTest {

    private static final URL BASE_URL = url("https://example.com/acme/1");

    /**
     * Test that an empty {@link JSON} is empty.
     */
    @Test
    public void testEmpty() {
        JSON empty = JSON.empty();
        assertThat(empty.toString()).isEqualTo("{}");
        assertThat(empty.toMap().keySet()).isEmpty();
    }

    /**
     * Test parsers.
     */
    @Test
    public void testParsers() throws IOException {
        String json = "{\"foo\":\"a-text\",\n\"bar\":123}";

        JSON fromString = JSON.parse(json);
        assertThatJson(fromString.toString()).isEqualTo(json);
        Map<String, Object> map = fromString.toMap();
        assertThat(map).hasSize(2);
        assertThat(map.keySet()).containsExactlyInAnyOrder("foo", "bar");
        assertThat(map.get("foo")).isEqualTo("a-text");
        assertThat(map.get("bar")).isEqualTo(123L);

        try (InputStream in = new ByteArrayInputStream(json.getBytes(UTF_8))) {
            JSON fromStream = JSON.parse(in);
            assertThatJson(fromStream.toString()).isEqualTo(json);
            Map<String, Object> map2 = fromStream.toMap();
            assertThat(map2).hasSize(2);
            assertThat(map2.keySet()).containsExactlyInAnyOrder("foo", "bar");
            assertThat(map2.get("foo")).isEqualTo("a-text");
            assertThat(map2.get("bar")).isEqualTo(123L);
        }
    }

    /**
     * Test that bad JSON fails.
     */
    @Test
    public void testParsersBadJSON() {
        assertThrows(AcmeProtocolException.class,
                () -> JSON.parse("This is no JSON.")
        );
    }

    /**
     * Test all object related methods.
     */
    @Test
    public void testObject() {
        JSON json = TestUtils.getJSON("datatypes");

        assertThat(json.keySet()).containsExactlyInAnyOrder(
                    "text", "number", "boolean", "uri", "url", "date", "array",
                    "collect", "status", "binary", "duration", "problem", "encoded");
        assertThat(json.contains("text")).isTrue();
        assertThat(json.contains("music")).isFalse();
        assertThat(json.get("text")).isNotNull();
        assertThat(json.get("music")).isNotNull();
    }

    /**
     * Test all array related methods.
     */
    @Test
    public void testArray() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("array").asArray();

        assertThat(array.isEmpty()).isFalse();
        assertThat(array).hasSize(4).doesNotContainNull();
    }

    /**
     * Test empty array.
     */
    @Test
    public void testEmptyArray() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("missingArray").asArray();

        assertThat(array.isEmpty()).isTrue();
        assertThat(array).hasSize(0);
        assertThat(array.stream().count()).isEqualTo(0L);
    }

    /**
     * Test all array iterator related methods.
     */
    @Test
    public void testArrayIterator() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("array").asArray();

        Iterator<JSON.Value> it = array.iterator();
        assertThat(it).isNotNull();

        assertThat(it.hasNext()).isTrue();
        assertThat(it.next().asString()).isEqualTo("foo");

        assertThat(it.hasNext()).isTrue();
        assertThat(it.next().asInt()).isEqualTo(987);

        assertThat(it.hasNext()).isTrue();
        assertThat(it.next().asArray()).hasSize(3);

        assertThat(it.hasNext()).isTrue();
        assertThrows(UnsupportedOperationException.class, it::remove);
        assertThat(it.next().asObject()).isNotNull();

        assertThat(it.hasNext()).isFalse();
        assertThrows(NoSuchElementException.class, it::next);
    }

    /**
     * Test the array stream.
     */
    @Test
    public void testArrayStream() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("array").asArray();

        List<JSON.Value> streamValues = array.stream().collect(Collectors.toList());

        List<JSON.Value> iteratorValues = new ArrayList<>();
        Iterator<JSON.Value> it = array.iterator();
        while (it.hasNext()) {
            iteratorValues.add(it.next());
        }

        assertThat(streamValues).containsAll(iteratorValues);
    }

    /**
     * Test all getters on existing values.
     */
    @Test
    public void testGetter() {
        Instant date = LocalDate.of(2016, 1, 8).atStartOfDay(ZoneId.of("UTC")).toInstant();

        JSON json = TestUtils.getJSON("datatypes");

        assertThat(json.get("text").asString()).isEqualTo("lorem ipsum");
        assertThat(json.get("number").asInt()).isEqualTo(123);
        assertThat(json.get("boolean").asBoolean()).isTrue();
        assertThat(json.get("uri").asURI()).isEqualTo(URI.create("mailto:foo@example.com"));
        assertThat(json.get("url").asURL()).isEqualTo(url("http://example.com"));
        assertThat(json.get("date").asInstant()).isEqualTo(date);
        assertThat(json.get("status").asStatus()).isEqualTo(Status.VALID);
        assertThat(json.get("binary").asBinary()).isEqualTo("Chainsaw".getBytes());
        assertThat(json.get("duration").asDuration()).hasSeconds(86400L);

        assertThat(json.get("text").isPresent()).isTrue();
        assertThat(json.get("text").optional().isPresent()).isTrue();
        assertThat(json.get("text").map(Value::asString).isPresent()).isTrue();

        JSON.Array array = json.get("array").asArray();
        assertThat(array.get(0).asString()).isEqualTo("foo");
        assertThat(array.get(1).asInt()).isEqualTo(987);

        JSON.Array array2 = array.get(2).asArray();
        assertThat(array2.get(0).asInt()).isEqualTo(1);
        assertThat(array2.get(1).asInt()).isEqualTo(2);
        assertThat(array2.get(2).asInt()).isEqualTo(3);

        JSON sub = array.get(3).asObject();
        assertThat(sub.get("test").asString()).isEqualTo("ok");

        JSON encodedSub = json.get("encoded").asEncodedObject();
        assertThatJson(encodedSub.toString()).isEqualTo("{\"key\":\"value\"}");

        Problem problem = json.get("problem").asProblem(BASE_URL);
        assertThat(problem).isNotNull();
        assertThat(problem.getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:rateLimited"));
        assertThat(problem.getDetail()).isEqualTo("too many requests");
        assertThat(problem.getInstance()).isEqualTo(URI.create("https://example.com/documents/errors.html"));
    }

    /**
     * Test that getters are null safe.
     */
    @Test
    public void testNullGetter() {
        JSON json = TestUtils.getJSON("datatypes");

        assertThat(json.get("none")).isNotNull();
        assertThat(json.get("none").isPresent()).isFalse();
        assertThat(json.get("none").optional().isPresent()).isFalse();
        assertThat(json.get("none").map(Value::asString).isPresent()).isFalse();

        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asString(),
                "asString");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asURI(),
                "asURI");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asURL(),
                "asURL");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asInstant(),
                "asInstant");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asDuration(),
                "asDuration");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asObject(),
                "asObject");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asEncodedObject(),
                "asEncodedObject");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asStatus(),
                "asStatus");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asBinary(),
                "asBinary");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asProblem(BASE_URL),
                "asProblem");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asInt(),
                "asInt");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("none").asBoolean(),
                "asBoolean");
    }

    /**
     * Test that wrong getters return an exception.
     */
    @Test
    public void testWrongGetter() {
        JSON json = TestUtils.getJSON("datatypes");

        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asObject(),
                "asObject");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asEncodedObject(),
                "asEncodedObject");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asArray(),
                "asArray");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asInt(),
                "asInt");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asURI(),
                "asURI");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asURL(),
                "asURL");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asInstant(),
                "asInstant");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asDuration(),
                "asDuration");
        assertThrows(AcmeProtocolException.class,
                () -> json.get("text").asProblem(BASE_URL),
                "asProblem");
    }

    /**
     * Test that serialization works correctly.
     */
    @Test
    public void testSerialization() throws IOException, ClassNotFoundException {
        JSON originalJson = TestUtils.getJSON("newAuthorizationResponse");

        // Serialize
        byte[] data;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
                oos.writeObject(originalJson);
            }
            data = out.toByteArray();
        }

        // Deserialize
        JSON testJson;
        try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {
            try (ObjectInputStream ois = new ObjectInputStream(in)) {
                testJson = (JSON) ois.readObject();
            }
        }

        assertThat(testJson).isNotSameAs(originalJson);
        assertThat(testJson.toString()).isNotEmpty();
        assertThatJson(testJson.toString()).isEqualTo(originalJson.toString());
    }

}
