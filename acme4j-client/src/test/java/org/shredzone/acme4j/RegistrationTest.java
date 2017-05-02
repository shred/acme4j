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
import static org.shredzone.acme4j.util.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.util.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.Registration.EditableRegistration;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Registration}.
 */
public class RegistrationTest {

    private URL resourceUrl  = url("http://example.com/acme/resource");
    private URL locationUrl  = url("http://example.com/acme/registration");
    private URI agreementUri = URI.create("http://example.com/agreement.pdf");

    /**
     * Test that a registration can be updated.
     */
    @Test
    public void testUpdateRegistration() throws AcmeException, IOException, URISyntaxException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private JSON jsonResponse;
            private Integer response;

            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(locationUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("updateRegistration").toString()));
                assertThat(session, is(notNullValue()));
                jsonResponse = getJSON("updateRegistrationResponse");
                response = HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public void sendRequest(URL url, Session session) {
                if (url("https://example.com/acme/acct/1/orders").equals(url)) {
                    jsonResponse = new JSONBuilder()
                                .array("orders", "https://example.com/acme/order/1")
                                .toJSON();
                    response = HttpURLConnection.HTTP_OK;
                    return;
                }

                response = HttpURLConnection.HTTP_NOT_FOUND;
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(response, not(nullValue()));
                return response;
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
            public URL getLink(String relation) {
                return null;
            }

            @Override
            public Collection<URI> getLinks(String relation) {
                switch(relation) {
                    case "terms-of-service": return Arrays.asList(agreementUri);
                    default: return null;
                }
            }
        };

        Session session = provider.createSession();
        Registration registration = new Registration(session, locationUrl);
        registration.update();

        assertThat(session.getKeyIdentifier(), is(locationUrl.toString()));
        assertThat(registration.getLocation(), is(locationUrl));
        assertThat(registration.getTermsOfServiceAgreed(), is(true));
        assertThat(registration.getContacts(), hasSize(1));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));
        assertThat(registration.getStatus(), is(Status.VALID));

        Iterator<Order> orderIt = registration.getOrders();
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
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                requestWasSent.set(true);
                assertThat(url, is(locationUrl));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateRegistrationResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public URL getLink(String relation) {
                return null;
            }

            @Override
            public Collection<URI> getLinks(String relation) {
                switch(relation) {
                    case "terms-of-service": return Arrays.asList(agreementUri);
                    default: return null;
                }
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUrl);

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(registration.getTermsOfServiceAgreed(), is(true));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(registration.getTermsOfServiceAgreed(), is(true));
        assertThat(registration.getStatus(), is(Status.VALID));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that a new {@link Authorization} can be created.
     */
    @Test
    public void testOrderCertificate() throws Exception {
        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");
        Instant notBefore = parseTimestamp("2016-01-01T00:00:00Z");
        Instant notAfter = parseTimestamp("2016-01-08T00:00:00Z");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("requestOrderRequest").toString()));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("requestOrderResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        Session session = provider.createSession();

        provider.putTestResource(Resource.NEW_ORDER, resourceUrl);

        Registration registration = new Registration(session, locationUrl);
        Order order = registration.orderCertificate(csr, notBefore, notAfter);

        assertThat(order.getCsr(), is(csr));
        assertThat(order.getNotBefore(), is(parseTimestamp("2016-01-01T00:10:00Z")));
        assertThat(order.getNotAfter(), is(parseTimestamp("2016-01-08T00:10:00Z")));
        assertThat(order.getExpires(), is(parseTimestamp("2016-01-10T00:00:00Z")));
        assertThat(order.getStatus(), is(Status.PENDING));
        assertThat(order.getLocation(), is(locationUrl));
        assertThat(order.getAuthorizations(), is(notNullValue()));
        assertThat(order.getAuthorizations().size(), is(2));

        provider.close();
    }

    /**
     * Test that a domain can be pre-authorized.
     */
    @Test
    public void testPreAuthorizeDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAuthorizationRequest").toString()));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED));
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

        Session session = provider.createSession();

        Http01Challenge httpChallenge = new Http01Challenge(session);
        Dns01Challenge dnsChallenge = new Dns01Challenge(session);

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);
        provider.putTestChallenge(Http01Challenge.TYPE, httpChallenge);
        provider.putTestChallenge(Dns01Challenge.TYPE, dnsChallenge);

        String domainName = "example.org";

        Registration registration = new Registration(session, locationUrl);
        Authorization auth = registration.preAuthorizeDomain(domainName);

        assertThat(auth.getDomain(), is(domainName));
        assertThat(auth.getStatus(), is(Status.PENDING));
        assertThat(auth.getExpires(), is(nullValue()));
        assertThat(auth.getLocation(), is(locationUrl));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

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
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newAuthorizationRequest").toString()));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                Problem problem = TestUtils.createProblem(problemType, problemDetail, resourceUrl);
                throw new AcmeServerException(problem);
            }
        };

        Session session = provider.createSession();

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUrl);

        Registration registration = new Registration(session, locationUrl);

        try {
            registration.preAuthorizeDomain("example.org");
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

        Session session = provider.createSession();
        Registration registration = Registration.bind(session, locationUrl);

        try {
            registration.preAuthorizeDomain(null);
            fail("null domain was accepted");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            registration.preAuthorizeDomain("");
            fail("empty domain string was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            registration.preAuthorizeDomain("example.com");
            fail("preauthorization was accepted");
        } catch (AcmeException ex) {
            // expected
            assertThat(ex.getMessage(), is("Server does not allow pre-authorization"));
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
            public void sendSignedRequest(URL url, JSONBuilder payload, Session session) {
                try {
                    assertThat(url, is(locationUrl));
                    assertThat(session, is(notNullValue()));
                    assertThat(session.getKeyPair(), is(sameInstance(oldKeyPair)));

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
                    expectedPayload.append("\"account\":\"").append(resourceUrl).append("\",");
                    expectedPayload.append("\"newKey\":{");
                    expectedPayload.append("\"kty\":\"").append(TestUtils.D_KTY).append("\",");
                    expectedPayload.append("\"e\":\"").append(TestUtils.D_E).append("\",");
                    expectedPayload.append("\"n\":\"").append(TestUtils.D_N).append("\"");
                    expectedPayload.append("}}");
                    assertThat(decodedPayload, sameJSONAs(expectedPayload.toString()));
                } catch (JoseException ex) {
                    fail("decoding inner payload failed");
                }
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public URL getLocation() {
                return resourceUrl;
            }
        };

        provider.putTestResource(Resource.KEY_CHANGE, locationUrl);

        Session session = new Session(new URI(TestUtils.ACME_SERVER_URI), oldKeyPair) {
            @Override
            public AcmeProvider provider() {
                return provider;
            };
        };

        assertThat(session.getKeyPair(), is(sameInstance(oldKeyPair)));

        Registration registration = new Registration(session, resourceUrl);
        registration.changeKey(newKeyPair);

        assertThat(session.getKeyPair(), is(sameInstance(newKeyPair)));
    }

    /**
     * Test that the same account key is not accepted for change.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testChangeSameKey() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider();
        Session session = provider.createSession();

        Registration registration = new Registration(session, locationUrl);
        registration.changeKey(session.getKeyPair());

        provider.close();
    }

    /**
     * Test that a registration can be deactivated.
     */
    @Test
    public void testDeactivate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                JSON json = claims.toJSON();
                assertThat(json.get("status").asString(), is("deactivated"));
                assertThat(url, is(locationUrl));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("deactivateRegistrationResponse");
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUrl);
        registration.deactivate();

        assertThat(registration.getStatus(), is(Status.DEACTIVATED));

        provider.close();
    }

    /**
     * Test that a registration can be modified.
     */
    @Test
    public void testModify() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(locationUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("modifyRegistration").toString()));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("modifyRegistrationResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUrl);

        EditableRegistration editable = registration.modify();
        assertThat(editable, notNullValue());

        editable.addContact("mailto:foo2@example.com");
        editable.getContacts().add(URI.create("mailto:foo3@example.com"));
        editable.commit();

        assertThat(registration.getLocation(), is(locationUrl));
        assertThat(registration.getContacts().size(), is(2));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));
        assertThat(registration.getContacts().get(1), is(URI.create("mailto:foo3@example.com")));

        provider.close();
    }

}
