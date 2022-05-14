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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
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
        assertThat(empty.toString(), is("{}"));
        assertThat(empty.toMap().keySet(), is(empty()));
    }

    /**
     * Test parsers.
     */
    @Test
    public void testParsers() throws IOException {
        String json = "{\"foo\":\"a-text\",\n\"bar\":123}";

        JSON fromString = JSON.parse(json);
        assertThat(fromString.toString(), is(sameJSONAs(json)));
        Map<String, Object> map = fromString.toMap();
        assertThat(map.size(), is(2));
        assertThat(map.keySet(), containsInAnyOrder("foo", "bar"));
        assertThat(map.get("foo"), is("a-text"));
        assertThat(map.get("bar"), is(123L));

        try (InputStream in = new ByteArrayInputStream(json.getBytes(UTF_8))) {
            JSON fromStream = JSON.parse(in);
            assertThat(fromStream.toString(), is(sameJSONAs(json)));
            Map<String, Object> map2 = fromStream.toMap();
            assertThat(map2.size(), is(2));
            assertThat(map2.keySet(), containsInAnyOrder("foo", "bar"));
            assertThat(map2.get("foo"), is("a-text"));
            assertThat(map2.get("bar"), is(123L));
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

        assertThat(json.keySet(), containsInAnyOrder(
                    "text", "number", "boolean", "uri", "url", "date", "array",
                    "collect", "status", "binary", "duration", "problem", "encoded"));
        assertThat(json.contains("text"), is(true));
        assertThat(json.contains("music"), is(false));
        assertThat(json.get("text"), is(notNullValue()));
        assertThat(json.get("music"), is(notNullValue()));
    }

    /**
     * Test all array related methods.
     */
    @Test
    public void testArray() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("array").asArray();

        assertThat(array.size(), is(4));
        assertThat(array.isEmpty(), is(false));
        assertThat(array.get(0), is(notNullValue()));
        assertThat(array.get(1), is(notNullValue()));
        assertThat(array.get(2), is(notNullValue()));
        assertThat(array.get(3), is(notNullValue()));
    }

    /**
     * Test empty array.
     */
    @Test
    public void testEmptyArray() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("missingArray").asArray();

        assertThat(array.size(), is(0));
        assertThat(array.isEmpty(), is(true));
        assertThat(array.stream().count(), is(0L));
    }

    /**
     * Test all array iterator related methods.
     */
    @Test
    public void testArrayIterator() {
        JSON json = TestUtils.getJSON("datatypes");
        JSON.Array array = json.get("array").asArray();

        Iterator<JSON.Value> it = array.iterator();
        assertThat(it, is(notNullValue()));

        assertThat(it.hasNext(), is(true));
        assertThat(it.next().asString(), is("foo"));

        assertThat(it.hasNext(), is(true));
        assertThat(it.next().asInt(), is(987));

        assertThat(it.hasNext(), is(true));
        assertThat(it.next().asArray().size(), is(3));

        assertThat(it.hasNext(), is(true));
        assertThrows(UnsupportedOperationException.class, it::remove);
        assertThat(it.next().asObject(), is(notNullValue()));

        assertThat(it.hasNext(), is(false));
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

        assertThat(streamValues, contains(iteratorValues.toArray()));
    }

    /**
     * Test all getters on existing values.
     */
    @Test
    public void testGetter() {
        Instant date = LocalDate.of(2016, 1, 8).atStartOfDay(ZoneId.of("UTC")).toInstant();

        JSON json = TestUtils.getJSON("datatypes");

        assertThat(json.get("text").asString(), is("lorem ipsum"));
        assertThat(json.get("number").asInt(), is(123));
        assertThat(json.get("boolean").asBoolean(), is(true));
        assertThat(json.get("uri").asURI(), is(URI.create("mailto:foo@example.com")));
        assertThat(json.get("url").asURL(), is(url("http://example.com")));
        assertThat(json.get("date").asInstant(), is(date));
        assertThat(json.get("status").asStatus(), is(Status.VALID));
        assertThat(json.get("binary").asBinary(), is("Chainsaw".getBytes()));
        assertThat(json.get("duration").asDuration(), is(Duration.ofSeconds(86400)));

        assertThat(json.get("text").isPresent(), is(true));
        assertThat(json.get("text").optional().isPresent(), is(true));
        assertThat(json.get("text").map(Value::asString).isPresent(), is(true));

        JSON.Array array = json.get("array").asArray();
        assertThat(array.get(0).asString(), is("foo"));
        assertThat(array.get(1).asInt(), is(987));

        JSON.Array array2 = array.get(2).asArray();
        assertThat(array2.get(0).asInt(), is(1));
        assertThat(array2.get(1).asInt(), is(2));
        assertThat(array2.get(2).asInt(), is(3));

        JSON sub = array.get(3).asObject();
        assertThat(sub.get("test").asString(), is("ok"));

        JSON encodedSub = json.get("encoded").asEncodedObject();
        assertThat(encodedSub.toString(), is(sameJSONAs("{\"key\":\"value\"}")));

        Problem problem = json.get("problem").asProblem(BASE_URL);
        assertThat(problem, is(notNullValue()));
        assertThat(problem.getType(), is(URI.create("urn:ietf:params:acme:error:rateLimited")));
        assertThat(problem.getDetail(), is("too many requests"));
        assertThat(problem.getInstance(), is(URI.create("https://example.com/documents/errors.html")));
    }

    /**
     * Test that getters are null safe.
     */
    @Test
    public void testNullGetter() {
        JSON json = TestUtils.getJSON("datatypes");

        assertThat(json.get("none"), is(notNullValue()));
        assertThat(json.get("none").isPresent(), is(false));
        assertThat(json.get("none").optional().isPresent(), is(false));
        assertThat(json.get("none").map(Value::asString).isPresent(), is(false));

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

        assertThat(testJson, not(sameInstance(originalJson)));
        assertThat(testJson.toString(), not(emptyOrNullString()));
        assertThat(testJson.toString(), is(sameJSONAs(originalJson.toString())));
    }

}
