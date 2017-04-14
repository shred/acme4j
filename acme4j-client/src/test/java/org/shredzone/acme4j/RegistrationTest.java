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
import static org.shredzone.acme4j.util.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
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
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Registration}.
 */
public class RegistrationTest {

    private URI resourceUri  = URI.create("http://example.com/acme/resource");
    private URI locationUri  = URI.create("http://example.com/acme/registration");
    private URI agreementUri = URI.create("http://example.com/agreement.pdf");
    private URI chainUri     = URI.create("http://example.com/acme/chain");

    /**
     * Test that a registration can be updated.
     */
    @Test
    public void testUpdateRegistration() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private JSON jsonResponse;
            private Integer response;

            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("updateRegistration")));
                assertThat(session, is(notNullValue()));
                jsonResponse = getJsonAsObject("updateRegistrationResponse");
                response = HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public void sendRequest(URI uri, Session session) {
                if (URI.create("https://example.com/acme/reg/1/authz").equals(uri)) {
                    jsonResponse = new JSONBuilder()
                                .array("authorizations", "https://example.com/acme/auth/1")
                                .toJSON();
                    response = HttpURLConnection.HTTP_OK;
                    return;
                }

                if (URI.create("https://example.com/acme/reg/1/cert").equals(uri)) {
                    jsonResponse = new JSONBuilder()
                                .array("certificates", "https://example.com/acme/cert/1")
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
            public URI getLocation() {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    case "next": return null;
                    default: return null;
                }
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUri);
        registration.update();

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(registration.getContacts(), hasSize(1));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));
        assertThat(registration.getStatus(), is(Status.GOOD));

        Iterator<Authorization> authIt = registration.getAuthorizations();
        assertThat(authIt, not(nullValue()));
        assertThat(authIt.next().getLocation(),
                        is(URI.create("https://example.com/acme/auth/1")));
        assertThat(authIt.hasNext(), is(false));

        Iterator<Certificate> certIt = registration.getCertificates();
        assertThat(certIt, not(nullValue()));
        assertThat(certIt.next().getLocation(),
                        is(URI.create("https://example.com/acme/cert/1")));
        assertThat(certIt.hasNext(), is(false));

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
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                requestWasSent.set(true);
                assertThat(uri, is(locationUri));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJsonAsObject("updateRegistrationResponse");
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUri);

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(registration.getStatus(), is(Status.GOOD));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that a new {@link Authorization} can be created.
     */
    @Test
    public void testAuthorizeDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newAuthorizationRequest")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJsonAsObject("newAuthorizationResponse");
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }
        };

        Session session = provider.createSession();

        Http01Challenge httpChallenge = new Http01Challenge(session);
        Dns01Challenge dnsChallenge = new Dns01Challenge(session);

        provider.putTestResource(Resource.NEW_AUTHZ, resourceUri);
        provider.putTestChallenge(Http01Challenge.TYPE, httpChallenge);
        provider.putTestChallenge(Dns01Challenge.TYPE, dnsChallenge);

        String domainName = "example.org";

        Registration registration = new Registration(session, locationUri);
        Authorization auth = registration.authorizeDomain(domainName);

        assertThat(auth.getDomain(), is(domainName));
        assertThat(auth.getStatus(), is(Status.PENDING));
        assertThat(auth.getExpires(), is(nullValue()));
        assertThat(auth.getLocation(), is(locationUri));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        assertThat(auth.getCombinations(), hasSize(2));
        assertThat(auth.getCombinations().get(0), containsInAnyOrder(
                        (Challenge) httpChallenge));
        assertThat(auth.getCombinations().get(1), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        provider.close();
    }

    /**
     * Test that a bad domain parameter is not accepted.
     */
    @Test
    public void testAuthorizeBadDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider();
        Session session = provider.createSession();
        Registration registration = Registration.bind(session, locationUri);

        try {
            registration.authorizeDomain(null);
            fail("null domain was accepted");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            registration.authorizeDomain("");
            fail("empty domain string was accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        provider.close();
    }

    /**
     * Test that a certificate can be requested and is delivered synchronously.
     */
    @Test
    public void testRequestCertificateSync() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URI uri, Session session) {
                fail("Attempted to download the certificate. Should be downloaded already!");
            }

            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequestWithDate")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public X509Certificate readCertificate() {
                return originalCert;
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "up": return chainUri;
                    default: return null;
                }
            }
        };

        provider.putTestResource(Resource.NEW_CERT, resourceUri);

        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");
        ZoneId utc = ZoneId.of("UTC");
        Instant notBefore = LocalDate.of(2016, 1, 1).atStartOfDay(utc).toInstant();
        Instant notAfter = LocalDate.of(2016, 1, 8).atStartOfDay(utc).toInstant();

        Registration registration = new Registration(provider.createSession(), locationUri);
        Certificate cert = registration.requestCertificate(csr, notBefore, notAfter);

        assertThat(cert.download(), is(originalCert));
        assertThat(cert.getLocation(), is(locationUri));
        assertThat(cert.getChainLocation(), is(chainUri));

        provider.close();
    }

    /**
     * Test that a certificate can be requested and is delivered asynchronously.
     */
    @Test
    public void testRequestCertificateAsync() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequest")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "up": return chainUri;
                    default: return null;
                }
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }
        };

        provider.putTestResource(Resource.NEW_CERT, resourceUri);

        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");

        Registration registration = new Registration(provider.createSession(), locationUri);
        Certificate cert = registration.requestCertificate(csr);

        assertThat(cert.getLocation(), is(locationUri));
        assertThat(cert.getChainLocation(), is(chainUri));

        provider.close();
    }

    /**
     * Test that an unparseable certificate can be requested, and at least its location
     * is made available.
     */
    @Test
    public void testRequestCertificateBrokenSync() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequestWithDate")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public X509Certificate readCertificate() {
                throw new AcmeProtocolException("Failed to read certificate");
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "up": return chainUri;
                    default: return null;
                }
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }
        };

        provider.putTestResource(Resource.NEW_CERT, resourceUri);

        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");
        ZoneId utc = ZoneId.of("UTC");
        Instant notBefore = LocalDate.of(2016, 1, 1).atStartOfDay(utc).toInstant();
        Instant notAfter = LocalDate.of(2016, 1, 8).atStartOfDay(utc).toInstant();

        Registration registration = new Registration(provider.createSession(), locationUri);
        Certificate cert = registration.requestCertificate(csr, notBefore, notAfter);

        assertThat(cert.getLocation(), is(locationUri));
        assertThat(cert.getChainLocation(), is(chainUri));

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
            public void sendSignedRequest(URI uri, JSONBuilder payload, Session session) {
                try {
                    assertThat(uri, is(locationUri));
                    assertThat(session, is(notNullValue()));
                    assertThat(session.getKeyPair(), is(sameInstance(oldKeyPair)));

                    JSON json = payload.toJSON();
                    assertThat(json.get("resource").asString(), is("key-change")); // Required by Let's Encrypt

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
                    expectedPayload.append("\"account\":\"").append(resourceUri).append("\",");
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
            public URI getLocation() {
                return resourceUri;
            }
        };

        provider.putTestResource(Resource.KEY_CHANGE, locationUri);

        Session session = new Session(new URI(TestUtils.ACME_SERVER_URI), oldKeyPair) {
            @Override
            public AcmeProvider provider() {
                return provider;
            };
        };

        assertThat(session.getKeyPair(), is(sameInstance(oldKeyPair)));

        Registration registration = new Registration(session, resourceUri);
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

        Registration registration = new Registration(session, locationUri);
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
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                JSON json = claims.toJSON();
                assertThat(json.get("resource").asString(), is("reg"));
                assertThat(json.get("status").asString(), is("deactivated"));
                assertThat(uri, is(locationUri));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUri);
        registration.deactivate();

        provider.close();
    }

    /**
     * Test that a registration can be modified.
     */
    @Test
    public void testModify() throws Exception {
        final URI agreementUri = URI.create("http://example.com/agreement.pdf");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("modifyRegistration")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJsonAsObject("modifyRegistrationResponse");
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        Registration registration = new Registration(provider.createSession(), locationUri);

        EditableRegistration editable = registration.modify();
        assertThat(editable, notNullValue());

        editable.setAgreement(agreementUri);
        editable.addContact("mailto:foo2@example.com");
        editable.getContacts().add(URI.create("mailto:foo3@example.com"));
        editable.commit();

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(registration.getContacts().size(), is(2));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));
        assertThat(registration.getContacts().get(1), is(URI.create("mailto:foo3@example.com")));

        provider.close();
    }

}
