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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

import org.junit.Test;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Unit test for {@link JSON}.
 */
public class JSONTest {

    /**
     * Test that an empty {@link JSON} is empty.
     */
    @Test
    public void testEmpty() {
        JSON empty = JSON.empty();
        assertThat(empty.toString(), is("{}"));
    }

    /**
     * Test parsers.
     */
    @Test
    public void testParsers() throws IOException {
        String json = "{\"foo\":\"a-text\",\n\"bar\":123}";

        JSON fromString = JSON.parse(json);
        assertThat(fromString.toString(), is(sameJSONAs(json)));

        try (InputStream in = new ByteArrayInputStream(json.getBytes("utf-8"))) {
            JSON fromStream = JSON.parse(in);
            assertThat(fromStream.toString(), is(sameJSONAs(json)));
        }
    }

    /**
     * Test that bad JSON fails.
     */
    @Test(expected = AcmeProtocolException.class)
    public void testParsersBadJSON() throws IOException {
        JSON.parse("This is no JSON.");
    }

    /**
     * Test all object related methods.
     */
    @Test
    public void testObject() {
        JSON json = TestUtils.getJsonAsObject("json");

        assertThat(json.keySet(), containsInAnyOrder(
                    "text", "number", "boolean", "uri", "url", "date", "array",
                    "collect", "status", "binary"));
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
        JSON json = TestUtils.getJsonAsObject("json");
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
        JSON json = TestUtils.getJsonAsObject("json");
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
        JSON json = TestUtils.getJsonAsObject("json");
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
        try {
            it.remove();
            fail("was able to remove from array");
        } catch (UnsupportedOperationException ex) {
            // expected
        }
        assertThat(it.next().asObject(), is(notNullValue()));

        assertThat(it.hasNext(), is(false));
        try {
            it.next();
            fail("next past last element");
        } catch (NoSuchElementException ex) {
            // expected
        }
    }

    /**
     * Test the array stream.
     */
    @Test
    public void testArrayStream() {
        JSON json = TestUtils.getJsonAsObject("json");
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
    public void testGetter() throws MalformedURLException {
        Instant date = LocalDate.of(2016, 1, 8).atStartOfDay(ZoneId.of("UTC")).toInstant();

        JSON json = TestUtils.getJsonAsObject("json");

        assertThat(json.get("text").asString(), is("lorem ipsum"));
        assertThat(json.get("number").asInt(), is(123));
        assertThat(json.get("boolean").asBoolean(), is(true));
        assertThat(json.get("uri").asURI(), is(URI.create("mailto:foo@example.com")));
        assertThat(json.get("url").asURL(), is(new URL("http://example.com")));
        assertThat(json.get("date").asInstant(), is(date));
        assertThat(json.get("status").asStatusOrElse(Status.INVALID), is(Status.VALID));
        assertThat(json.get("binary").asBinary(), is("Chainsaw".getBytes()));

        JSON.Array array = json.get("array").asArray();
        assertThat(array.get(0).asString(), is("foo"));
        assertThat(array.get(1).asInt(), is(987));

        JSON.Array array2 = array.get(2).asArray();
        assertThat(array2.get(0).asInt(), is(1));
        assertThat(array2.get(1).asInt(), is(2));
        assertThat(array2.get(2).asInt(), is(3));

        JSON sub = array.get(3).asObject();
        assertThat(sub.get("test").asString(), is("ok"));
    }

    /**
     * Test that getters are null safe.
     */
    @Test
    public void testNullGetter() throws MalformedURLException {
        JSON json = TestUtils.getJsonAsObject("json");

        assertThat(json.get("none"), is(notNullValue()));
        assertThat(json.get("none").asString(), is(nullValue()));
        assertThat(json.get("none").asURI(), is(nullValue()));
        assertThat(json.get("none").asURL(), is(nullValue()));
        assertThat(json.get("none").asInstant(), is(nullValue()));
        assertThat(json.get("none").asObject(), is(nullValue()));
        assertThat(json.get("none").asStatusOrElse(Status.INVALID), is(Status.INVALID));
        assertThat(json.get("none").asBinary(), is(nullValue()));

        try {
            json.get("none").asInt();
            fail("asInt did not fail");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("none").asBoolean();
            fail("asBoolean did not fail");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("none").required();
            fail("required did not fail");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        JSON.Value textv = json.get("text");
        assertThat(textv.required(), is(textv));
    }

    /**
     * Test that wrong getters return an exception.
     */
    @Test
    public void testWrongGetter() throws MalformedURLException {
        JSON json = TestUtils.getJsonAsObject("json");

        try {
            json.get("text").asObject();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("text").asArray();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("text").asInt();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("text").asURI();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("text").asURL();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }

        try {
            json.get("text").asInstant();
            fail("no exception was thrown");
        } catch (AcmeProtocolException ex) {
            // expected
        }
    }

    /**
     * Test that serialization works correctly.
     */
    @Test
    public void testSerialization() throws IOException, ClassNotFoundException {
        JSON originalJson = TestUtils.getJsonAsObject("newAuthorizationResponse");

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
        assertThat(testJson.toString(), not(isEmptyOrNullString()));
        assertThat(testJson.toString(), is(sameJSONAs(originalJson.toString())));
    }

}
