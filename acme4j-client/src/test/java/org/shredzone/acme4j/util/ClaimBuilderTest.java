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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;

/**
 * Unit test for {@link ClaimBuilder}.
 */
public class ClaimBuilderTest {

    /**
     * Test that an empty claimbuilder is empty.
     */
    @Test
    public void testEmpty() {
        ClaimBuilder cb = new ClaimBuilder();
        assertThat(cb.toString(), is("{}"));
    }

    /**
     * Test basic data types. Also test that methods return {@code this}, that existing
     * keys are replaced, and that the output keys are in lexicographical order.
     */
    @Test
    public void testBasics() {
        ClaimBuilder res;

        ClaimBuilder cb = new ClaimBuilder();
        res = cb.put("fooStr", "String");
        assertThat(res, is(sameInstance(cb)));

        res = cb.put("fooInt", 123);
        assertThat(res, is(sameInstance(cb)));

        res = cb.put("fooInt", 456);
        assertThat(res, is(sameInstance(cb)));

        assertThat(cb.toString(), is("{\"fooInt\":456,\"fooStr\":\"String\"}"));

        Map<String, Object> map = cb.toMap();
        assertThat(map.keySet(), hasSize(2));
        assertThat(map, allOf(
                hasEntry("fooInt", (Object) 456),
                hasEntry("fooStr", (Object) "String")
        ));
    }

    /**
     * Test date type.
     */
    @Test
    public void testDate() {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT+2"));
        cal.clear();
        cal.set(2016, Calendar.JUNE, 1, 5, 13, 46);

        ClaimBuilder cb = new ClaimBuilder();
        cb.put("fooDate", cal.getTime());

        assertThat(cb.toString(), is("{\"fooDate\":\"2016-06-01T03:13:46Z\"}"));
    }

    /**
     * Test resources.
     */
    @Test
    public void testResource() {
        ClaimBuilder res;

        ClaimBuilder cb = new ClaimBuilder();
        res = cb.putResource("new-reg");
        assertThat(res, is(sameInstance(cb)));
        assertThat(cb.toString(), is("{\"resource\":\"new-reg\"}"));

        res = cb.putResource(Resource.NEW_AUTHZ);
        assertThat(res, is(sameInstance(cb)));
        assertThat(cb.toString(), is("{\"resource\":\"new-authz\"}"));
    }

    /**
     * Test method to add maps.
     */
    @Test
    public void testMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("fooStr", "String");
        map.put("fooInt", 123);

        ClaimBuilder res;

        ClaimBuilder cb = new ClaimBuilder();
        res = cb.putAll(map);
        assertThat(res, is(sameInstance(cb)));
        assertThat(cb.toString(), is("{\"fooInt\":123,\"fooStr\":\"String\"}"));
    }

    /**
     * Test base64 encoding.
     */
    @Test
    public void testBase64() {
        byte[] data = "abc123".getBytes();

        ClaimBuilder res;

        ClaimBuilder cb = new ClaimBuilder();
        res = cb.putBase64("foo", data);
        assertThat(res, is(sameInstance(cb)));
        assertThat(cb.toString(), is("{\"foo\":\"YWJjMTIz\"}"));
    }

    /**
     * Test JWK.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testKey() throws IOException, NoSuchAlgorithmException, JoseException {
        KeyPair keyPair = TestUtils.createKeyPair();

        ClaimBuilder res;

        ClaimBuilder cb = new ClaimBuilder();
        res = cb.putKey("foo", keyPair.getPublic());
        assertThat(res, is(sameInstance(cb)));

        Map<String, Object> json = JsonUtil.parseJson(cb.toString());
        assertThat(json, hasKey("foo"));

        Map<String, String> jwk = (Map<String, String>) json.get("foo");
        assertThat(jwk.keySet(), hasSize(3));
        assertThat(jwk, hasEntry("n", TestUtils.N));
        assertThat(jwk, hasEntry("e", TestUtils.E));
        assertThat(jwk, hasEntry("kty", TestUtils.KTY));
    }

    /**
     * Test sub claims (objects).
     */
    @Test
    public void testObject() {
        ClaimBuilder cb = new ClaimBuilder();
        ClaimBuilder sub = cb.object("sub");
        assertThat(sub, not(sameInstance(cb)));

        assertThat(cb.toString(), is("{\"sub\":{}}"));

        cb.put("foo", 123);
        sub.put("foo", 456);

        assertThat(cb.toString(), is("{\"foo\":123,\"sub\":{\"foo\":456}}"));
    }

    /**
     * Test arrays.
     */
    @Test
    public void testArray() {
        ClaimBuilder res;

        ClaimBuilder cb1 = new ClaimBuilder();
        res = cb1.array("ar", new Object[0]);
        assertThat(res, is(sameInstance(cb1)));
        assertThat(cb1.toString(), is("{\"ar\":[]}"));

        ClaimBuilder cb2 = new ClaimBuilder();
        res = cb2.array("ar", 123);
        assertThat(res, is(sameInstance(cb2)));
        assertThat(cb2.toString(), is("{\"ar\":[123]}"));

        ClaimBuilder cb3 = new ClaimBuilder();
        res = cb3.array("ar", 123, "foo", 456);
        assertThat(res, is(sameInstance(cb3)));
        assertThat(cb3.toString(), is("{\"ar\":[123,\"foo\",456]}"));
    }

}
