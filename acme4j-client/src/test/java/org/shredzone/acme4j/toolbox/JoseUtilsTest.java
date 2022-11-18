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
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.URL;
import java.util.Base64;
import java.util.HashMap;

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
        var resourceUrl = url("http://example.com/acme/resource");
        var accountKey = TestUtils.createKeyPair();
        var nonce = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());
        var payload = new JSONBuilder();
        payload.put("foo", 123);
        payload.put("bar", "a-string");

        var jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, payload, nonce, TestUtils.ACCOUNT_URL)
                .toMap();

        var encodedHeader = jose.get("protected").toString();
        var encodedSignature = jose.get("signature").toString();
        var encodedPayload = jose.get("payload").toString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce).append("\",");
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(TestUtils.ACCOUNT_URL).append('"');
        expectedHeader.append('}');

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8))
                .isEqualTo(expectedHeader.toString());
        assertThatJson(new String(URL_DECODER.decode(encodedPayload), UTF_8))
                .isEqualTo("{\"foo\":123,\"bar\":\"a-string\"}");
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test if a JOSE ACME POST-as-GET request is correctly created.
     */
    @Test
    public void testCreateJosePostAsGetRequest() throws Exception {
        var resourceUrl = url("http://example.com/acme/resource");
        var accountKey = TestUtils.createKeyPair();
        var nonce = URL_ENCODER.encodeToString("foo-nonce-1-foo".getBytes());

        var jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, null, nonce, TestUtils.ACCOUNT_URL)
                .toMap();

        var encodedHeader = jose.get("protected").toString();
        var encodedSignature = jose.get("signature").toString();
        var encodedPayload = jose.get("payload").toString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"nonce\":\"").append(nonce).append("\",");
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"kid\":\"").append(TestUtils.ACCOUNT_URL).append('"');
        expectedHeader.append('}');

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8))
                .isEqualTo(expectedHeader.toString());
        assertThat(new String(URL_DECODER.decode(encodedPayload), UTF_8)).isEmpty();
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test if a JOSE ACME Key-Change request is correctly created.
     */
    @Test
    public void testCreateJoseKeyChangeRequest() throws Exception {
        var resourceUrl = url("http://example.com/acme/resource");
        var accountKey = TestUtils.createKeyPair();
        var payload = new JSONBuilder();
        payload.put("foo", 123);
        payload.put("bar", "a-string");

        var jose = JoseUtils
                .createJoseRequest(resourceUrl, accountKey, payload, null, null)
                .toMap();

        var encodedHeader = jose.get("protected").toString();
        var encodedSignature = jose.get("signature").toString();
        var encodedPayload = jose.get("payload").toString();

        var expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"url\":\"").append(resourceUrl).append("\",");
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\": {");
        expectedHeader.append("\"kty\": \"").append(TestUtils.KTY).append("\",");
        expectedHeader.append("\"e\": \"").append(TestUtils.E).append("\",");
        expectedHeader.append("\"n\": \"").append(TestUtils.N).append("\"}");
        expectedHeader.append("}");

        assertThatJson(new String(URL_DECODER.decode(encodedHeader), UTF_8))
                .isEqualTo(expectedHeader.toString());
        assertThatJson(new String(URL_DECODER.decode(encodedPayload), UTF_8))
                .isEqualTo("{\"foo\":123,\"bar\":\"a-string\"}");
        assertThat(encodedSignature).isNotEmpty();

        var jws = new JsonWebSignature();
        jws.setCompactSerialization(CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature));
        jws.setKey(accountKey.getPublic());
        assertThat(jws.verifySignature()).isTrue();
    }

    /**
     * Test if an external account binding is correctly created.
     */
    @Test
    public void testCreateExternalAccountBinding() throws Exception {
        var accountKey = TestUtils.createKeyPair();
        var keyIdentifier = "NCC-1701";
        var macKey = TestUtils.createSecretKey("SHA-256");
        var resourceUrl = url("http://example.com/acme/resource");

        var binding = JoseUtils.createExternalAccountBinding(
                keyIdentifier, accountKey.getPublic(), macKey, resourceUrl);

        var encodedHeader = binding.get("protected").toString();
        var encodedSignature = binding.get("signature").toString();
        var encodedPayload = binding.get("payload").toString();
        var serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);

        assertExternalAccountBinding(serialized, resourceUrl, keyIdentifier, macKey);
    }

    /**
     * Test if public key is correctly converted to JWK structure.
     */
    @Test
    public void testPublicKeyToJWK() throws Exception {
        var json = JoseUtils.publicKeyToJWK(TestUtils.createKeyPair().getPublic());
        assertThat(json).hasSize(3);
        assertThat(json.get("kty")).isEqualTo(TestUtils.KTY);
        assertThat(json.get("n")).isEqualTo(TestUtils.N);
        assertThat(json.get("e")).isEqualTo(TestUtils.E);
    }

    /**
     * Test if JWK structure is correctly converted to public key.
     */
    @Test
    public void testJWKToPublicKey() throws Exception {
        var json = new HashMap<String, Object>();
        json.put("kty", TestUtils.KTY);
        json.put("n", TestUtils.N);
        json.put("e", TestUtils.E);
        var key = JoseUtils.jwkToPublicKey(json);
        assertThat(key.getEncoded()).isEqualTo(TestUtils.createKeyPair().getPublic().getEncoded());
    }

    /**
     * Test if thumbprint is correctly computed.
     */
    @Test
    public void testThumbprint() throws Exception {
        var thumb = JoseUtils.thumbprint(TestUtils.createKeyPair().getPublic());
        var encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(thumb);
        assertThat(encoded).isEqualTo(TestUtils.THUMBPRINT);
    }

    /**
     * Test if RSA using SHA-256 keys are properly detected.
     */
    @Test
    public void testRsaKey() throws Exception {
        var rsaKeyPair = TestUtils.createKeyPair();
        var jwk = PublicJsonWebKey.Factory.newPublicJwk(rsaKeyPair.getPublic());

        var type = JoseUtils.keyAlgorithm(jwk);
        assertThat(type).isEqualTo("RS256");
    }

    /**
     * Test if ECDSA using NIST P-256 curve and SHA-256 keys are properly detected.
     */
    @Test
    public void testP256ECKey() throws Exception {
        var ecKeyPair = TestUtils.createECKeyPair("secp256r1");
        var jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        var type = JoseUtils.keyAlgorithm(jwk);
        assertThat(type).isEqualTo("ES256");
    }

    /**
     * Test if ECDSA using NIST P-384 curve and SHA-384 keys are properly detected.
     */
    @Test
    public void testP384ECKey() throws Exception {
        var ecKeyPair = TestUtils.createECKeyPair("secp384r1");
        var jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        var type = JoseUtils.keyAlgorithm(jwk);
        assertThat(type).isEqualTo("ES384");
    }

    /**
     * Test if ECDSA using NIST P-521 curve and SHA-512 keys are properly detected.
     */
    @Test
    public void testP521ECKey() throws Exception {
        var ecKeyPair = TestUtils.createECKeyPair("secp521r1");
        var jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        var type = JoseUtils.keyAlgorithm(jwk);
        assertThat(type).isEqualTo("ES512");
    }

    /**
     * Test if MAC key algorithms are properly detected.
     */
    @Test
    public void testMacKey() throws Exception {
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-256"))).isEqualTo("HS256");
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-384"))).isEqualTo("HS384");
        assertThat(JoseUtils.macKeyAlgorithm(TestUtils.createSecretKey("SHA-512"))).isEqualTo("HS512");
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
            var jws = new JsonWebSignature();
            jws.setCompactSerialization(serialized);
            jws.setKey(macKey);
            assertThat(jws.verifySignature()).isTrue();

            assertThat(jws.getHeader("url")).isEqualTo(resourceUrl.toString());
            assertThat(jws.getHeader("kid")).isEqualTo(keyIdentifier);
            assertThat(jws.getHeader("alg")).isEqualTo("HS256");

            var decodedPayload = jws.getPayload();
            var expectedPayload = new StringBuilder();
            expectedPayload.append('{');
            expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
            expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
            expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
            expectedPayload.append("}");
            assertThatJson(decodedPayload).isEqualTo(expectedPayload.toString());
        } catch (JoseException ex) {
            fail(ex);
        }
    }

}
