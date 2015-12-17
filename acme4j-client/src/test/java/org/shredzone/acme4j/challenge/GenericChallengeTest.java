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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge.Status;
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
        assertThat(challenge.getUri(), is(nullValue()));
        assertThat(challenge.getValidated(), is(nullValue()));

        // Unmarshall a challenge JSON
        challenge.unmarshall(TestUtils.getJsonAsMap("genericChallenge"));

        // Test unmarshalled values
        assertThat(challenge.getType(), is("generic-01"));
        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getUri(), is(new URI("http://example.com/challenge/123")));
        assertThat(challenge.getValidated(), is("2015-12-12T17:19:36.336785823Z"));
    }

    /**
     * Test get and put methods.
     */
    public void testGetPut() {
        GenericChallenge challenge = new GenericChallenge();

        challenge.put("a-string", "foo");
        challenge.put("a-number", 1234);

        assertThat((String) challenge.get("a-string"), is("foo"));
        assertThat((Integer) challenge.get("a-number"), is(1234));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.marshall(cb);
        assertThat(cb.toString(), sameJSONAs("{\"a-string\":\"foo\",\"a-number\":1234}")
                .allowingExtraUnexpectedFields());
    }

    /**
     * Test that marshalling results in an identical JSON like the one that was
     * unmarshalled.
     */
    @Test
    public void testMarshall() throws JoseException {
        String json = TestUtils.getJson("genericChallenge");

        GenericChallenge challenge = new GenericChallenge();
        challenge.unmarshall(JsonUtil.parseJson(json));

        ClaimBuilder cb = new ClaimBuilder();
        challenge.marshall(cb);

        assertThat(cb.toString(), sameJSONAs(json));
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

}
