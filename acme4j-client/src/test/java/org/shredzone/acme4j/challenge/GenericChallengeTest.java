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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link GenericChallenge}.
 *
 * @author Richard "Shred" Körber
 */
public class GenericChallengeTest {

    /**
     * Test that after unmarshalling, the challenge properties are set correctly.
     */
    @Test
    public void testUnmarshall() throws URISyntaxException {
        GenericChallenge challenge = new GenericChallenge();

        // Test default values
        assertThat(challenge.getType(), is(nullValue()));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getLocation(), is(nullValue()));
        assertThat(challenge.getValidated(), is(nullValue()));

        // Unmarshall a challenge JSON
        challenge.unmarshall(TestUtils.getJsonAsMap("genericChallenge"));

        // Test unmarshalled values
        assertThat(challenge.getType(), is("generic-01"));
        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(new URI("http://example.com/challenge/123")));
        assertThat(challenge.getValidated(), is("2015-12-12T17:19:36.336785823Z"));
    }

    /**
     * Test that {@link GenericChallenge#respond(ClaimBuilder)} contains the type.
     */
    @Test
    public void testRespond() throws JoseException {
        String json = TestUtils.getJson("genericChallenge");

        GenericChallenge challenge = new GenericChallenge();
        challenge.unmarshall(JsonUtil.parseJson(json));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.respond(cb);

        assertThat(cb.toString(), sameJSONAs("{\"type\"=\"generic-01\"}"));
    }

    /**
     * Test that an exception is thrown on challenge type mismatch.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNotAcceptable() throws URISyntaxException {
        HttpChallenge challenge = new HttpChallenge();
        challenge.unmarshall(TestUtils.getJsonAsMap("dnsChallenge"));
    }

    /**
     * Test that the test keypair's thumbprint is correct.
     */
    @Test
    public void testJwkThumbprint() throws IOException, JoseException {
        StringBuilder json = new StringBuilder();
        json.append('{');
        json.append("\"e\":\"").append(TestUtils.E).append("\",");
        json.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
        json.append("\"n\":\"").append(TestUtils.N).append("\"");
        json.append('}');

        KeyPair keypair = TestUtils.createKeyPair();

        // Test the JWK raw output. The JSON string must match the assert string
        // exactly, as the thumbprint is a digest of that string.
        final JsonWebKey jwk = JsonWebKey.Factory.newJwk(keypair.getPublic());
        ClaimBuilder cb = new ClaimBuilder();
        cb.putAll(jwk.toParams(OutputControlLevel.PUBLIC_ONLY));
        assertThat(cb.toString(), is(json.toString()));

        // Make sure the returned thumbprint is correct
        byte[] thumbprint = GenericChallenge.jwkThumbprint(keypair.getPublic());
        assertThat(thumbprint, is(Base64Url.decode(TestUtils.THUMBPRINT)));
    }

    /**
     * Test that challenge serialization works correctly.
     */
    @Test
    public void testSerialization() throws IOException, ClassNotFoundException {
        HttpChallenge originalChallenge = new HttpChallenge();
        originalChallenge.unmarshall(TestUtils.getJsonAsMap("httpChallenge"));

        // Serialize
        byte[] data;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
                oos.writeObject(originalChallenge);
            }
            data = out.toByteArray();
        }

        // Deserialize
        Challenge testChallenge;
        try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {
            try (ObjectInputStream ois = new ObjectInputStream(in)) {
                testChallenge = (Challenge) ois.readObject();
            }
        }

        assertThat(testChallenge, not(sameInstance((Challenge) originalChallenge)));
        assertThat(testChallenge, is(instanceOf(HttpChallenge.class)));
        assertThat(testChallenge.getType(), is(HttpChallenge.TYPE));
        assertThat(testChallenge.getStatus(), is(Status.PENDING));
        assertThat(((HttpChallenge )testChallenge).getToken(), is("rSoI9JpyvFi-ltdnBW0W1DjKstzG7cHixjzcOjwzAEQ"));
    }

}
