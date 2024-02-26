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
package org.shredzone.acme4j;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.jose4j.jwx.CompactSerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.JoseUtilsTest;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AccountBuilder}.
 */
public class AccountBuilderTest {

    private final URL resourceUrl = url("http://example.com/acme/resource");
    private final URL locationUrl = url("http://example.com/acme/account");

    /**
     * Test if a new account can be created.
     */
    @Test
    public void testRegistration() throws Exception {
        var accountKey = TestUtils.createKeyPair();

        var provider = new TestableConnectionProvider() {
            private boolean isUpdate;

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(login).isNotNull();
                assertThat(url).isEqualTo(locationUrl);
                assertThat(isUpdate).isFalse();
                isUpdate = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(session).isNotNull();
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("newAccount").toString());
                assertThat(keypair).isEqualTo(accountKey);
                isUpdate = false;
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("newAccountResponse");
            }
        };

        provider.putTestResource(Resource.NEW_ACCOUNT, resourceUrl);

        var builder = new AccountBuilder();
        builder.addContact("mailto:foo@example.com");
        builder.agreeToTermsOfService();
        builder.useKeyPair(accountKey);

        var session = provider.createSession();
        var login = builder.createLogin(session);

        assertThat(login.getAccountLocation()).isEqualTo(locationUrl);

        var account = login.getAccount();
        assertThat(account.getTermsOfServiceAgreed().orElseThrow()).isTrue();
        assertThat(account.getLocation()).isEqualTo(locationUrl);
        assertThat(account.hasExternalAccountBinding()).isFalse();
        assertThat(account.getKeyIdentifier()).isEmpty();

        provider.close();
    }

    /**
     * Test if a new account with Key Identifier can be created.
     */
    @ParameterizedTest
    @CsvSource({
            "SHA-256,HS256,",      "SHA-384,HS384,",      "SHA-512,HS512,",
            "SHA-256,HS256,HS256", "SHA-384,HS384,HS384", "SHA-512,HS512,HS512",
            "SHA-512,HS256,HS256"
    })
    public void testRegistrationWithKid(String keyAlg, String expectedMacAlg, @Nullable String macAlg) throws Exception {
        var accountKey = TestUtils.createKeyPair();
        var keyIdentifier = "NCC-1701";
        var macKey = TestUtils.createSecretKey(keyAlg);

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(session).isNotNull();
                assertThat(url).isEqualTo(resourceUrl);
                assertThat(keypair).isEqualTo(accountKey);

                var binding = claims.toJSON()
                                .get("externalAccountBinding")
                                .asObject();

                var encodedHeader = binding.get("protected").asString();
                var encodedSignature = binding.get("signature").asString();
                var encodedPayload = binding.get("payload").asString();
                var serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);

                JoseUtilsTest.assertExternalAccountBinding(serialized, resourceUrl, keyIdentifier, macKey, expectedMacAlg);

                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public JSON readJsonResponse() {
                return JSON.empty();
            }
        };

        provider.putTestResource(Resource.NEW_ACCOUNT, resourceUrl);
        provider.putMetadata("externalAccountRequired", true);

        var builder = new AccountBuilder();
        builder.useKeyPair(accountKey);
        builder.withKeyIdentifier(keyIdentifier, AcmeUtils.base64UrlEncode(macKey.getEncoded()));
        if (macAlg != null) {
            builder.withMacAlgorithm(macAlg);
        }

        var session = provider.createSession();
        var login = builder.createLogin(session);

        assertThat(login.getAccountLocation()).isEqualTo(locationUrl);

        provider.close();
    }

    /**
     * Test if invalid mac algorithms are rejected.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"foo", "null", "false", "none", "HS-256", "hs256", "HS128", "RS256"})
    public void testRejectInvalidMacAlg(@Nullable String macAlg) {
        assertThatException().isThrownBy(() -> {
            new AccountBuilder().withMacAlgorithm(macAlg);
        }).isInstanceOfAny(IllegalArgumentException.class, NullPointerException.class);
    }

    /**
     * Test if an existing account is properly returned.
     */
    @Test
    public void testOnlyExistingRegistration() throws Exception {
        var accountKey = TestUtils.createKeyPair();

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(session).isNotNull();
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("newAccountOnlyExisting").toString());
                assertThat(keypair).isEqualTo(accountKey);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("newAccountResponse");
            }
        };

        provider.putTestResource(Resource.NEW_ACCOUNT, resourceUrl);

        var builder = new AccountBuilder();
        builder.useKeyPair(accountKey);
        builder.onlyExisting();

        var session = provider.createSession();
        var login = builder.createLogin(session);

        assertThat(login.getAccountLocation()).isEqualTo(locationUrl);

        provider.close();
    }

    @Test
    public void testEmailAddresses() {
        var builder = Mockito.spy(AccountBuilder.class);
        builder.addEmail("foo@example.com");
        Mockito.verify(builder).addContact(Mockito.eq("mailto:foo@example.com"));

        // mailto is still accepted if present
        builder.addEmail("mailto:bar@example.com");
        Mockito.verify(builder).addContact(Mockito.eq("mailto:bar@example.com"));
    }
}
