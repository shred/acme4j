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
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.Account.EditableAccount;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Account}.
 */
public class AccountTest {

    private URL resourceUrl  = url("http://example.com/acme/resource");
    private URL locationUrl  = url(TestUtils.ACCOUNT_URL);
    private URL agreementUrl = url("http://example.com/agreement.pdf");

    /**
     * Test that a account can be updated.
     */
    @Test
    public void testUpdateAccount() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private JSON jsonResponse;

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(locationUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("updateAccount").toString()));
                assertThat(login, is(notNullValue()));
                jsonResponse = getJSON("updateAccountResponse");
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                if (url("https://example.com/acme/acct/1/orders").equals(url)) {
                    jsonResponse = new JSONBuilder()
                                .array("orders", Arrays.asList("https://example.com/acme/order/1"))
                                .toJSON();
                } else {
                    jsonResponse = getJSON("updateAccountResponse");
                }
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return jsonResponse;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                return Collections.emptyList();
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // do nothing
            }
        };

        Login login = provider.createLogin();
        Account account = new Account(login);
        account.update();

        assertThat(login.getAccountLocation(), is(locationUrl));
        assertThat(account.getLocation(), is(locationUrl));
        assertThat(account.getTermsOfServiceAgreed(), is(true));
        assertThat(account.getContacts(), hasSize(1));
        assertThat(account.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));
        assertThat(account.getStatus(), is(Status.VALID));
        assertThat(account.hasExternalAccountBinding(), is(true));
        assertThat(account.getKeyIdentifier(), is("NCC-1701"));

        Iterator<Order> orderIt = account.getOrders();
        assertThat(orderIt, not(nullValue()));
        assertThat(orderIt.next().getLocation(), is(url("https://example.com/acme/order/1")));
        assertThat(orderIt.hasNext(), is(false));

        provider.close();
    }

    /**
     * Test lazy loading.
     */
    @Test
    public void testLazyLoading() throws AcmeException, IOException {
        final AtomicBoolean requestWasSent = new AtomicBoolean(false);

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                requestWasSent.set(true);
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAccountResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                switch(relation) {
                    case "termsOfService": return Arrays.asList(agreementUrl);
                    default: return null;
                }
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // do nothing
            }
        };

        Account account = new Account(provider.createLogin());

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(account.getTermsOfServiceAgreed(), is(true));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(account.getTermsOfServiceAgreed(), is(true));
        assertThat(account.getStatus(), is(Status.VALID));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that a domain can be pre-authorized.
     */
    @Test
    public void testPreAuthorizeDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAuthorizationRequest").toString()));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("newAuthorizationResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        Login login = provider.createLogin();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);
        provider.putTestChallenge(Http01Challenge.TYPE, Http01Challenge::new);
        provider.putTestChallenge(Dns01Challenge.TYPE, Dns01Challenge::new);

        String domainName = "example.org";

        Account account = new Account(login);
        Authorization auth = account.preAuthorizeDomain(domainName);

        assertThat(auth.getIdentifier().getDomain(), is(domainName));
        assertThat(auth.getStatus(), is(Status.PENDING));
        assertThat(auth.getExpires(), is(nullValue()));
        assertThat(auth.getLocation(), is(locationUrl));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE)));

        provider.close();
    }

    /**
     * Test that a domain pre-authorization can fail.
     */
    @Test
    public void testNoPreAuthorizeDomain() throws Exception {
        URI problemType = URI.create("urn:ietf:params:acme:error:rejectedIdentifier");
        String problemDetail = "example.org is blacklisted";

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAuthorizationRequest").toString()));
                assertThat(login, is(notNullValue()));

                Problem problem = TestUtils.createProblem(problemType, problemDetail, resourceUrl);
                throw new AcmeServerException(problem);
            }
        };

        Login login = provider.createLogin();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);

        Account account = new Account(login);

        try {
            account.preAuthorizeDomain("example.org");
            fail("preauthorization was accepted");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is(problemType));
            assertThat(ex.getMessage(), is(problemDetail));
        }

        provider.close();
    }

    /**
     * Test that a bad domain parameter is not accepted.
     */
    @Test
    public void testAuthorizeBadDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider();
        // just provide a resource record so the provider returns a directory
        provider.putTestResource(Resource.NEW_NONCE, resourceUrl);

        Login login = provider.createLogin();
        Account account = login.getAccount();

        try {
            account.preAuthorizeDomain(null);
            fail("null domain was accepted");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            account.preAuthorizeDomain("");
            fail("empty domain string was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            account.preAuthorizeDomain("example.com");
            fail("preauthorization was accepted");
        } catch (AcmeException ex) {
            // expected
            assertThat(ex.getMessage(), is("Server does not offer newAuthz"));
        }

        provider.close();
    }

    /**
     * Test that the account key can be changed.
     */
    @Test
    public void testChangeKey() throws Exception {
        final KeyPair oldKeyPair = TestUtils.createKeyPair();
        final KeyPair newKeyPair = TestUtils.createDomainKeyPair();

        final TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder payload, Login login) {
                try {
                    assertThat(url, is(locationUrl));
                    assertThat(login, is(notNullValue()));
                    assertThat(login.getKeyPair(), is(sameInstance(oldKeyPair)));

                    JSON json = payload.toJSON();
                    String encodedHeader = json.get("protected").asString();
                    String encodedSignature = json.get("signature").asString();
                    String encodedPayload = json.get("payload").asString();

                    String serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setCompactSerialization(serialized);
                    jws.setKey(newKeyPair.getPublic());
                    assertThat(jws.verifySignature(), is(true));

                    String decodedPayload = jws.getPayload();

                    StringBuilder expectedPayload = new StringBuilder();
                    expectedPayload.append('{');
                    expectedPayload.append("\"account\":\"").append(locationUrl).append("\",");
                    expectedPayload.append("\"oldKey\":{");
                    expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
                    expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
                    expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
                    expectedPayload.append("}}");
                    assertThat(decodedPayload, sameJSONAs(expectedPayload.toString()));
                } catch (JoseException ex) {
                    fail("decoding inner payload failed");
                }

                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public URL getLocation() {
                return resourceUrl;
            }
        };

        provider.putTestResource(Resource.KEY_CHANGE, locationUrl);

        Session session = TestUtils.session(provider);
        Login login = new Login(locationUrl, oldKeyPair, session);

        assertThat(login.getKeyPair(), is(sameInstance(oldKeyPair)));

        Account account = new Account(login);
        account.changeKey(newKeyPair);

        assertThat(login.getKeyPair(), is(sameInstance(newKeyPair)));
    }

    /**
     * Test that the same account key is not accepted for change.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testChangeSameKey() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider();
        Login login = provider.createLogin();

        Account account = new Account(login);
        account.changeKey(login.getKeyPair());

        provider.close();
    }

    /**
     * Test that an account can be deactivated.
     */
    @Test
    public void testDeactivate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                JSON json = claims.toJSON();
                assertThat(json.get("status").asString(), is("deactivated"));
                assertThat(url, is(locationUrl));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("deactivateAccountResponse");
            }
        };

        Account account = new Account(provider.createLogin());
        account.deactivate();

        assertThat(account.getStatus(), is(Status.DEACTIVATED));

        provider.close();
    }

    /**
     * Test that an account can be modified.
     */
    @Test
    public void testModify() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(locationUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("modifyAccount").toString()));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("modifyAccountResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        Account account = new Account(provider.createLogin());
        account.setJSON(getJSON("newAccount"));

        EditableAccount editable = account.modify();
        assertThat(editable, notNullValue());

        editable.addContact("mailto:foo2@example.com");
        editable.getContacts().add(URI.create("mailto:foo3@example.com"));
        editable.commit();

        assertThat(account.getLocation(), is(locationUrl));
        assertThat(account.getContacts().size(), is(3));
        assertThat(account.getContacts().get(0), is(URI.create("mailto:foo@example.com")));
        assertThat(account.getContacts().get(1), is(URI.create("mailto:foo2@example.com")));
        assertThat(account.getContacts().get(2), is(URI.create("mailto:foo3@example.com")));

        provider.close();
    }

}
