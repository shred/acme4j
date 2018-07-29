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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AccountBuilder}.
 */
public class AccountBuilderTest {

    private URL resourceUrl = url("http://example.com/acme/resource");
    private URL locationUrl = url("http://example.com/acme/account");

    /**
     * Test if a new account can be created.
     */
    @Test
    public void testRegistration() throws Exception {
        KeyPair accountKey = TestUtils.createKeyPair();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean isUpdate;

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(login, is(notNullValue()));
                assertThat(url, is(locationUrl));
                assertThat(isUpdate, is(false));
                isUpdate = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(session, is(notNullValue()));
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAccount").toString()));
                assertThat(keypair, is(accountKey));
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

        AccountBuilder builder = new AccountBuilder();
        builder.addContact("mailto:foo@example.com");
        builder.agreeToTermsOfService();
        builder.useKeyPair(accountKey);

        Session session = provider.createSession();
        Login login = builder.createLogin(session);

        assertThat(login.getAccountLocation(), is(locationUrl));

        Account account = login.getAccount();
        assertThat(account.getTermsOfServiceAgreed(), is(true));
        assertThat(account.getLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test if a new account with Key Identifier can be created.
     */
    @Test
    public void testRegistrationWithKid() throws Exception {
        KeyPair accountKey = TestUtils.createKeyPair();
        String keyIdentifier = "NCC-1701";
        SecretKey macKey = TestUtils.createSecretKey("SHA-256");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                try {
                    assertThat(session, is(notNullValue()));
                    assertThat(url, is(resourceUrl));
                    assertThat(keypair, is(accountKey));

                    JSON binding = claims.toJSON()
                                    .get("externalAccountBinding")
                                    .asObject();

                    String encodedHeader = binding.get("protected").asString();
                    String encodedSignature = binding.get("signature").asString();
                    String encodedPayload = binding.get("payload").asString();

                    String serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);
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
                    ex.printStackTrace();
                    fail("decoding inner payload failed");
                }

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

        AccountBuilder builder = new AccountBuilder();
        builder.useKeyPair(accountKey);
        builder.withKeyIdentifier(keyIdentifier, AcmeUtils.base64UrlEncode(macKey.getEncoded()));

        Session session = provider.createSession();
        Login login = builder.createLogin(session);

        assertThat(login.getAccountLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test if an existing account is properly returned.
     */
    @Test
    public void testOnlyExistingRegistration() throws Exception {
        KeyPair accountKey = TestUtils.createKeyPair();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(session, is(notNullValue()));
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAccountOnlyExisting").toString()));
                assertThat(keypair, is(accountKey));
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

        AccountBuilder builder = new AccountBuilder();
        builder.useKeyPair(accountKey);
        builder.onlyExisting();

        Session session = provider.createSession();
        Login login = builder.createLogin(session);

        assertThat(login.getAccountLocation(), is(locationUrl));

        provider.close();
    }

}
