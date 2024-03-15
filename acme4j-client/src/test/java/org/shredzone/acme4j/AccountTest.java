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

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Account}.
 */
public class AccountTest {

    private final URL resourceUrl  = url("http://example.com/acme/resource");
    private final URL locationUrl  = url(TestUtils.ACCOUNT_URL);
    private final URL agreementUrl = url("http://example.com/agreement.pdf");

    /**
     * Test that a account can be updated.
     */
    @Test
    public void testUpdateAccount() throws AcmeException, IOException {
        var provider = new TestableConnectionProvider() {
            private JSON jsonResponse;

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("updateAccount").toString());
                assertThat(login).isNotNull();
                jsonResponse = getJSON("updateAccountResponse");
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                if ("https://example.com/acme/acct/1/orders".equals(url.toExternalForm())) {
                    jsonResponse = new JSONBuilder()
                                .array("orders", singletonList("https://example.com/acme/order/1"))
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
                return emptyList();
            }
        };

        var login = provider.createLogin();
        var account = new Account(login);
        account.update();

        assertThat(login.getAccountLocation()).isEqualTo(locationUrl);
        assertThat(account.getLocation()).isEqualTo(locationUrl);
        assertThat(account.getTermsOfServiceAgreed().orElseThrow()).isTrue();
        assertThat(account.getContacts()).hasSize(1);
        assertThat(account.getContacts().get(0)).isEqualTo(URI.create("mailto:foo2@example.com"));
        assertThat(account.getStatus()).isEqualTo(Status.VALID);
        assertThat(account.hasExternalAccountBinding()).isTrue();
        assertThat(account.getKeyIdentifier().orElseThrow()).isEqualTo("NCC-1701");

        var orderIt = account.getOrders();
        assertThat(orderIt).isNotNull();
        assertThat(orderIt.next().getLocation()).isEqualTo(url("https://example.com/acme/order/1"));
        assertThat(orderIt.hasNext()).isFalse();

        provider.close();
    }

    /**
     * Test lazy loading.
     */
    @Test
    public void testLazyLoading() throws IOException {
        var requestWasSent = new AtomicBoolean(false);

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                requestWasSent.set(true);
                assertThat(url).isEqualTo(locationUrl);
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
                    case "termsOfService": return singletonList(agreementUrl);
                    default: return emptyList();
                }
            }
        };

        var account = new Account(provider.createLogin());

        // Lazy loading
        assertThat(requestWasSent.get()).isFalse();
        assertThat(account.getTermsOfServiceAgreed().orElseThrow()).isTrue();
        assertThat(requestWasSent.get()).isTrue();

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(account.getTermsOfServiceAgreed().orElseThrow()).isTrue();
        assertThat(account.getStatus()).isEqualTo(Status.VALID);
        assertThat(requestWasSent.get()).isFalse();

        provider.close();
    }

    /**
     * Test that a domain can be pre-authorized.
     */
    @Test
    public void testPreAuthorizeDomain() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("newAuthorizationRequest").toString());
                assertThat(login).isNotNull();
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

        var login = provider.createLogin();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);
        provider.putTestChallenge(Http01Challenge.TYPE, Http01Challenge::new);
        provider.putTestChallenge(Dns01Challenge.TYPE, Dns01Challenge::new);

        var domainName = "example.org";

        var account = new Account(login);
        var auth = account.preAuthorize(Identifier.dns(domainName));

        assertThat(auth.getIdentifier().getDomain()).isEqualTo(domainName);
        assertThat(auth.getStatus()).isEqualTo(Status.PENDING);
        assertThat(auth.getExpires()).isEmpty();
        assertThat(auth.getLocation()).isEqualTo(locationUrl);

        assertThat(auth.getChallenges()).containsExactlyInAnyOrder(
                        provider.getChallenge(Http01Challenge.TYPE),
                        provider.getChallenge(Dns01Challenge.TYPE));

        provider.close();
    }

    /**
     * Test that pre-authorization with subdomains fails if not supported.
     */
    @Test
    public void testPreAuthorizeDomainSubdomainsFails() throws Exception {
        var provider = new TestableConnectionProvider();

        var login = provider.createLogin();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);

        assertThat(login.getSession().getMetadata().isSubdomainAuthAllowed()).isFalse();

        var account = new Account(login);

        assertThatExceptionOfType(AcmeNotSupportedException.class).isThrownBy(() ->
                account.preAuthorize(Identifier.dns("example.org").allowSubdomainAuth())
        );

        provider.close();
    }

    /**
     * Test that a domain can be pre-authorized, with allowed subdomains.
     */
    @Test
    public void testPreAuthorizeDomainSubdomains() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("newAuthorizationRequestSub").toString());
                assertThat(login).isNotNull();
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("newAuthorizationResponseSub");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        var login = provider.createLogin();

        provider.putMetadata("subdomainAuthAllowed", true);
        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);
        provider.putTestChallenge(Dns01Challenge.TYPE, Dns01Challenge::new);

        var domainName = "example.org";

        var account = new Account(login);
        var auth = account.preAuthorize(Identifier.dns(domainName).allowSubdomainAuth());

        assertThat(login.getSession().getMetadata().isSubdomainAuthAllowed()).isTrue();
        assertThat(auth.getIdentifier().getDomain()).isEqualTo(domainName);
        assertThat(auth.getStatus()).isEqualTo(Status.PENDING);
        assertThat(auth.getExpires()).isEmpty();
        assertThat(auth.getLocation()).isEqualTo(locationUrl);
        assertThat(auth.isSubdomainAuthAllowed()).isTrue();

        assertThat(auth.getChallenges()).containsExactlyInAnyOrder(
                provider.getChallenge(Dns01Challenge.TYPE));

        provider.close();
    }

    /**
     * Test that a domain pre-authorization can fail.
     */
    @Test
    public void testNoPreAuthorizeDomain() throws Exception {
        var problemType = URI.create("urn:ietf:params:acme:error:rejectedIdentifier");
        var problemDetail = "example.org is blacklisted";

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) throws AcmeException {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("newAuthorizationRequest").toString());
                assertThat(login).isNotNull();

                var problem = TestUtils.createProblem(problemType, problemDetail, resourceUrl);
                throw new AcmeServerException(problem);
            }
        };

        var login = provider.createLogin();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);

        var account = new Account(login);

        var ex = assertThrows(AcmeServerException.class, () ->
            account.preAuthorizeDomain("example.org")
        );
        assertThat(ex.getType()).isEqualTo(problemType);
        assertThat(ex.getMessage()).isEqualTo(problemDetail);

        provider.close();
    }

    /**
     * Test that a bad domain parameter is not accepted.
     */
    @Test
    public void testAuthorizeBadDomain() throws Exception {
        var provider = new TestableConnectionProvider();
        // just provide a resource record so the provider returns a directory
        provider.putTestResource(Resource.NEW_NONCE, resourceUrl);

        var login = provider.createLogin();
        var account = login.getAccount();

        assertThatNullPointerException()
                .isThrownBy(() -> account.preAuthorizeDomain(null));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> account.preAuthorizeDomain(""));
        assertThatExceptionOfType(AcmeNotSupportedException.class)
                .isThrownBy(() -> account.preAuthorizeDomain("example.com"))
                .withMessage("Server does not support newAuthz");

        provider.close();
    }

    /**
     * Test that the account key can be changed.
     */
    @Test
    public void testChangeKey() throws Exception {
        var oldKeyPair = TestUtils.createKeyPair();
        var newKeyPair = TestUtils.createDomainKeyPair();

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder payload, Login login) {
                try {
                    assertThat(url).isEqualTo(locationUrl);
                    assertThat(login).isNotNull();
                    assertThat(login.getKeyPair()).isSameAs(oldKeyPair);

                    var json = payload.toJSON();
                    var encodedHeader = json.get("protected").asString();
                    var encodedSignature = json.get("signature").asString();
                    var encodedPayload = json.get("payload").asString();

                    var serialized = CompactSerializer.serialize(encodedHeader, encodedPayload, encodedSignature);
                    var jws = new JsonWebSignature();
                    jws.setCompactSerialization(serialized);
                    jws.setKey(newKeyPair.getPublic());
                    assertThat(jws.verifySignature()).isTrue();

                    var decodedPayload = jws.getPayload();

                    var expectedPayload = new StringBuilder();
                    expectedPayload.append('{');
                    expectedPayload.append("\"account\":\"").append(locationUrl).append("\",");
                    expectedPayload.append("\"oldKey\":{");
                    expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
                    expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
                    expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
                    expectedPayload.append("}}");
                    assertThatJson(decodedPayload).isEqualTo(expectedPayload.toString());
                } catch (JoseException ex) {
                    fail(ex);
                }

                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        provider.putTestResource(Resource.KEY_CHANGE, locationUrl);

        var session = TestUtils.session(provider);
        var login = new Login(locationUrl, oldKeyPair, session);

        assertThat(login.getKeyPair()).isSameAs(oldKeyPair);

        var account = new Account(login);
        account.changeKey(newKeyPair);

        assertThat(login.getKeyPair()).isSameAs(newKeyPair);
    }

    /**
     * Test that the same account key is not accepted for change.
     */
    @Test
    public void testChangeSameKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            var provider = new TestableConnectionProvider();
            var login = provider.createLogin();

            var account = new Account(login);
            account.changeKey(login.getKeyPair());

            provider.close();
        });
    }

    /**
     * Test that an account can be deactivated.
     */
    @Test
    public void testDeactivate() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                var json = claims.toJSON();
                assertThat(json.get("status").asString()).isEqualTo("deactivated");
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("deactivateAccountResponse");
            }
        };

        var account = new Account(provider.createLogin());
        account.deactivate();

        assertThat(account.getStatus()).isEqualTo(Status.DEACTIVATED);

        provider.close();
    }

    /**
     * Test that a new order can be created.
     */
    @Test
    public void testNewOrder() throws AcmeException, IOException {
        var provider = new TestableConnectionProvider();
        var login = provider.createLogin();

        var account = new Account(login);
        assertThat(account.newOrder()).isNotNull();

        provider.close();
    }

    /**
     * Test that an account can be modified.
     */
    @Test
    public void testModify() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("modifyAccount").toString());
                assertThat(login).isNotNull();
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

        var account = new Account(provider.createLogin());
        account.setJSON(getJSON("newAccount"));

        var editable = account.modify();
        assertThat(editable).isNotNull();

        editable.addContact("mailto:foo2@example.com");
        editable.getContacts().add(URI.create("mailto:foo3@example.com"));
        editable.commit();

        assertThat(account.getLocation()).isEqualTo(locationUrl);
        assertThat(account.getContacts()).hasSize(3);
        assertThat(account.getContacts()).element(0).isEqualTo(URI.create("mailto:foo@example.com"));
        assertThat(account.getContacts()).element(1).isEqualTo(URI.create("mailto:foo2@example.com"));
        assertThat(account.getContacts()).element(2).isEqualTo(URI.create("mailto:foo3@example.com"));

        provider.close();
    }

}
