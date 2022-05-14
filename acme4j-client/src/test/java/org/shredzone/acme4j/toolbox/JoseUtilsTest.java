/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
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
import static org.junit.jupiter.api.Assertions.fail;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link JoseUtils}.
 */
public class JoseUtilsTest {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    /**
     * Test if a JOSE ACME POST request is correctly created.
     */
    @Test
    public void testCreateJosePostRequest() throws Exception {
        URL resourceUrl = url("http://example.com/acme/resource");
        KeyPair accountKey = TestUtils.createKeyPair();
        String nonce = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        JSONBuilder payload = new JSONBuilder();
        payload.put("foo", 123);
        payload.put("bar", "a-string");

        Map<String, Object> jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, payload, nonce, TestUtils.ACCOUNT_URL)
                .toMap();

        String encodedHeader = jose.get("protected").toString();
        String encodedSignature = jose.get("signature").toString();
        String encodedPayload = jose.get("payload").toString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce).append("\",");
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(TestUtils.ACCOUNT_URL).append('"');
        expectedHeader.append('}');

        assertThat(new String(URL_DECODER.decode(encodedHeader), UTF_8), sameJSONAs(expectedHeader.toString()));
        assertThat(new String(URL_DECODER.decode(encodedPayload), UTF_8), sameJSONAs("{\"foo\":123,\"bar\":\"a-string\"}"));
        assertThat(encodedSignature, not(emptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test if a JOSE ACME POST-as-GET request is correctly created.
     */
    @Test
    public void testCreateJosePostAsGetRequest() throws Exception {
        URL resourceUrl = url("http://example.com/acme/resource");
        KeyPair accountKey = TestUtils.createKeyPair();
        String nonce = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());

        Map<String, Object> jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, null, nonce, TestUtils.ACCOUNT_URL)
                .toMap();

        String encodedHeader = jose.get("protected").toString();
        String encodedSignature = jose.get("signature").toString();
        String encodedPayload = jose.get("payload").toString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce).append("\",");
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(TestUtils.ACCOUNT_URL).append('"');
        expectedHeader.append('}');

        assertThat(new String(URL_DECODER.decode(encodedHeader), UTF_8), sameJSONAs(expectedHeader.toString()));
        assertThat(new String(URL_DECODER.decode(encodedPayload), UTF_8), is(""));
        assertThat(encodedSignature, not(emptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test if a JOSE ACME Key-Change request is correctly created.
     */
    @Test
    public void testCreateJoseKeyChangeRequest() throws Exception {
        URL resourceUrl = url("http://example.com/acme/resource");
        KeyPair accountKey = TestUtils.createKeyPair();
        JSONBuilder payload = new JSONBuilder();
        payload.put("foo", 123);
        payload.put("bar", "a-string");

        Map<String, Object> jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, payload, null, null)
                .toMap();

        String encodedHeader = jose.get("protected").toString();
        String encodedSignature = jose.get("signature").toString();
        String encodedPayload = jose.get("payload").toString();

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\": {");
        expectedHeader.append("\"kty\": \"").append(TestUtils.KTY).append("\",");
        expectedHeader.append("\"e\": \"").append(TestUtils.E).append("\",");
        expectedHeader.append("\"n\": \"").append(TestUtils.N).append("\"}");
        expectedHeader.append("}");

        assertThat(new String(URL_DECODER.decode(encodedHeader), UTF_8), sameJSONAs(expectedHeader.toString()));
        assertThat(new String(URL_DECODER.decode(encodedPayload), UTF_8), sameJSONAs("{\"foo\":123,\"bar\":\"a-string\"}"));
        assertThat(encodedSignature, not(emptyOrNullString()));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature(), is(true));
    }

    /**
     * Test if an external account binding is correctly created.
     */
    @Test
    public void testCreateExternalAccountBinding() throws Exception {
        KeyPair accountKey = TestUtils.createKeyPair();
        String keyIdentifier = "NCC-1701";
        SecretKey macKey = TestUtils.createSecretKey("SHA-256");
        URL resourceUrl = url("http://example.com/acme/resource");

        Map<String, Object> binding = JoseUtils.createExternalAccountBinding(
                keyIdentifier, accountKey.getPublic(), macKey, resourceUrl);

        String encodedHeader = binding.get("protected").toString();
        String encodedSignature = binding.get("signature").toString();
        String encodedPayload = binding.get("payload").toString();
        String serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);

        assertExternalAccountBinding(serialized, resourceUrl, keyIdentifier, macKey);
    }

    /**
     * Test if public key is correctly converted to JWK structure.
     */
    @Test
    public void testPublicKeyToJWK() throws Exception {
        Map<String, Object> json = JoseUtils.publicKeyToJWK(TestUtils.createKeyPair().getPublic());
        assertThat(json.size(), is(3));
        assertThat(json.get("kty"), is(TestUtils.KTY));
        assertThat(json.get("n"), is(TestUtils.N));
        assertThat(json.get("e"), is(TestUtils.E));
    }

    /**
     * Test if JWK structure is correctly converted to public key.
     */
    @Test
    public void testJWKToPublicKey() throws Exception {
        Map<String, Object> json = new HashMap<>();
        json.put("kty", TestUtils.KTY);
        json.put("n", TestUtils.N);
        json.put("e", TestUtils.E);
        PublicKey key = JoseUtils.jwkToPublicKey(json);
        assertThat(key.getEncoded(), is(TestUtils.createKeyPair().getPublic().getEncoded()));
    }

    /**
     * Test if thumbprint is correctly computed.
     */
    @Test
    public void testThumbprint() throws Exception {
        byte[] thumb = JoseUtils.thumbprint(TestUtils.createKeyPair().getPublic());
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(thumb);
        assertThat(encoded, is(TestUtils.THUMBPRINT));
    }

    /**
     * Test if RSA using SHA-256 keys are properly detected.
     */
    @Test
    public void testRsaKey() throws Exception {
        KeyPair rsaKeyPair = TestUtils.createKeyPair();
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(rsaKeyPair.getPublic());

        String type = JoseUtils.keyAlgorithm(jwk);

        assertThat(type, is("RS256"));
    }

    /**
     * Test if ECDSA using NIST P-256 curve and SHA-256 keys are properly detected.
     */
    @Test
    public void testP256ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp256r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = JoseUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES256"));
    }

    /**
     * Test if ECDSA using NIST P-384 curve and SHA-384 keys are properly detected.
     */
    @Test
    public void testP384ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp384r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = JoseUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES384"));
    }

    /**
     * Test if ECDSA using NIST P-521 curve and SHA-512 keys are properly detected.
     */
    @Test
    public void testP521ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp521r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = JoseUtils.keyAlgorithm(jwk);

        assertThat(type, is("ES512"));
    }

    /**
     * Test if MAC key algorithms are properly detected.
     */
    @Test
    public void testMacKey() throws Exception {
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-256")), is("HS256"));
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-384")), is("HS384"));
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-512")), is("HS512"));
    }

    /**
     * Asserts that the serialized external account binding is valid. Unit test fails if
     * the account binding is invalid.
     *
     * @param serialized
     *         Serialized external account binding JOSE structure
     * @param resourceUrl
     *         Expected resource {@link URL}
     * @param keyIdentifier
     *         Expected key identifier
     * @param macKey
     *         Expected {@link SecretKey}
     */
    public static void assertExternalAccountBinding(String serialized, URL resourceUrl,
                                                    String keyIdentifier, SecretKey macKey) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(serialized);
            jws.setKey(macKey);
            assertThat(jws.verifySignature(), is(true));

            assertThat(jws.getHeader("url"), is(resourceUrl.toString()));
            assertThat(jws.getHeader("kid"), is(keyIdentifier));
            assertThat(jws.getHeader("alg"), is("HS256"));

            String decodedPayload = jws.getPayload();
            StringBuilder expectedPayload = new StringBuilder();
            expectedPayload.append('{');
            expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
            expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
            expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
            expectedPayload.append("}");
            assertThat(decodedPayload, sameJSONAs(expectedPayload.toString()));
        } catch (JoseException ex) {
            fail(ex);
        }
    }

}
