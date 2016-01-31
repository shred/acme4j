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
package org.shredzone.acme4j.impl;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;
import org.shredzone.acme4j.util.TimestampParser;

/**
 * Unit tests for {@link AbstractAcmeClient}.
 *
 * @author Richard "Shred" Körber
 */
public class AbstractAcmeClientTest {

    private URI resourceUri;
    private URI locationUri;
    private URI anotherLocationUri;
    private URI agreementUri;
    private KeyPair accountKeyPair;
    private Registration testRegistration;

    @Before
    public void setup() throws IOException, URISyntaxException {
        resourceUri = new URI("https://example.com/acme/some-resource");
        locationUri = new URI("https://example.com/acme/some-location");
        anotherLocationUri = new URI("https://example.com/acme/another-location");
        agreementUri = new URI("http://example.com/agreement.pdf");
        accountKeyPair = TestUtils.createKeyPair();
        testRegistration = new Registration(accountKeyPair);
    }

    /**
     * Test that a new {@link Registration} can be registered.
     */
    @Test
    public void testNewRegistration() throws AcmeException {
        Registration registration = new Registration(accountKeyPair);
        registration.addContact("mailto:foo@example.com");

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newRegistration")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URI getLocation() throws AcmeException {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) throws AcmeException {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.NEW_REG, resourceUri);

        client.newRegistration(registration);

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
    }

    /**
     * Test that a {@link Registration} can be modified.
     */
    @Test
    public void testModifyRegistration() throws AcmeException {
        Registration registration = new Registration(accountKeyPair);
        registration.setAgreement(agreementUri);
        registration.addContact("mailto:foo2@example.com");
        registration.setLocation(locationUri);

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("modifyRegistration")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public URI getLocation() throws AcmeException {
                return locationUri;
            }

            @Override
            public URI getLink(String relation) throws AcmeException {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        client.modifyRegistration(registration);

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
    }

    /**
     * Test that the account key can be changed.
     */
    @Test
    public void testChangeRegistrationKey() throws AcmeException, IOException {
        Registration registration = new Registration(accountKeyPair);
        registration.setLocation(locationUri);

        final KeyPair newKeyPair = TestUtils.createDomainKeyPair();

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                Map<String, Object> claimMap = claims.toMap();
                assertThat(claimMap.get("resource"), is((Object) "reg"));
                assertThat(claimMap.get("newKey"), not(nullValue()));

                try {
                    StringBuilder expectedPayload = new StringBuilder();
                    expectedPayload.append('{');
                    expectedPayload.append("\"resource\":\"reg\",");
                    expectedPayload.append("\"oldKey\":{");
                    expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
                    expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
                    expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
                    expectedPayload.append("}}");

                    String newKey = (String) claimMap.get("newKey");
                    JsonWebSignature jws = (JsonWebSignature) JsonWebSignature.fromCompactSerialization(newKey);
                    jws.setKey(newKeyPair.getPublic());
                    assertThat(jws.getPayload(), sameJSONAs(expectedPayload.toString()));
                } catch (JoseException ex) {
                    throw new AcmeException("Bad newKey", ex);
                }

                assertThat(uri, is(locationUri));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public URI getLocation() throws AcmeException {
                return locationUri;
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        client.changeRegistrationKey(registration, newKeyPair);
    }

    /**
     * Test that the same account key is not accepted for change
     */
    @Test(expected = IllegalArgumentException.class)
    public void testChangeRegistrationSameKey() throws AcmeException, IOException {
        Registration registration = new Registration(accountKeyPair);
        registration.setLocation(locationUri);

        Connection connection = new DummyConnection();
        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        client.changeRegistrationKey(registration, registration.getKeyPair());
    }

    /**
     * Test that a {@link Registration} can be recovered by contact-based recovery.
     */
    @Test
    public void testRecoverRegistration() throws AcmeException {
        Registration registration = new Registration(accountKeyPair);
        registration.addContact("mailto:foo@example.com");
        registration.setLocation(locationUri);

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("recoverRegistration")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URI getLocation() throws AcmeException {
                return anotherLocationUri;
            }

            @Override
            public URI getLink(String relation) throws AcmeException {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.RECOVER_REG, resourceUri);

        client.recoverRegistration(registration);

        assertThat(registration.getLocation(), is(anotherLocationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
    }

    /**
     * Test that a new {@link Authorization} can be created.
     */
    @Test
    public void testNewAuthorization() throws AcmeException {
        Authorization auth = new Authorization();
        auth.setDomain("example.org");

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newAuthorizationRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("newAuthorizationResponse");
            }

            @Override
            public URI getLocation() throws AcmeException {
                return locationUri;
            }
        };

        Http01Challenge httpChallenge = new Http01Challenge();
        Dns01Challenge dnsChallenge = new Dns01Challenge();

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.NEW_AUTHZ, resourceUri);
        client.putTestChallenge("http-01", httpChallenge);
        client.putTestChallenge("dns-01", dnsChallenge);

        client.newAuthorization(testRegistration, auth);

        assertThat(auth.getDomain(), is("example.org"));
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
    }

    /**
     * Test that {@link Authorization} are properly updated.
     */
    @Test
    public void testUpdateAuthorization() throws AcmeException {
        Authorization auth = new Authorization(locationUri);

        Connection connection = new DummyConnection() {
            @Override
            public int sendRequest(URI uri) throws AcmeException {
                assertThat(uri, is(locationUri));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("updateAuthorizationResponse");
            }
        };

        Http01Challenge httpChallenge = new Http01Challenge();
        Dns01Challenge dnsChallenge = new Dns01Challenge();

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestChallenge("http-01", httpChallenge);
        client.putTestChallenge("dns-01", dnsChallenge);

        client.updateAuthorization(auth);

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is(Status.VALID));
        assertThat(auth.getExpires(), is(TimestampParser.parse("2016-01-02T17:12:40Z")));
        assertThat(auth.getLocation(), is(locationUri));

        assertThat(auth.getChallenges(), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));

        assertThat(auth.getCombinations(), hasSize(2));
        assertThat(auth.getCombinations().get(0), containsInAnyOrder(
                        (Challenge) httpChallenge));
        assertThat(auth.getCombinations().get(1), containsInAnyOrder(
                        (Challenge) httpChallenge, (Challenge) dnsChallenge));
    }

    /**
     * Test that a {@link Challenge} can be triggered.
     */
    @Test
    public void testTriggerChallenge() throws AcmeException {
        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("triggerHttpChallengeRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("triggerHttpChallengeResponse");
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        Http01Challenge challenge = new Http01Challenge();
        challenge.unmarshall(getJsonAsMap("triggerHttpChallenge"));
        challenge.authorize(testRegistration);

        client.triggerChallenge(testRegistration, challenge);

        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getLocation(), is(locationUri));
    }

    /**
     * Test that a {@link Challenge} is properly updated.
     */
    @Test
    public void testUpdateChallenge() throws AcmeException {
        Connection connection = new DummyConnection() {
            @Override
            public int sendRequest(URI uri) throws AcmeException {
                assertThat(uri, is(locationUri));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("updateHttpChallengeResponse");
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        Challenge challenge = new Http01Challenge();
        challenge.unmarshall(getJsonAsMap("triggerHttpChallengeResponse"));

        client.updateChallenge(challenge);

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUri));
    }

    @Test
    public void testRestoreChallenge() throws AcmeException {
        Connection connection = new DummyConnection() {
            @Override
            public int sendRequest(URI uri) throws AcmeException {
                assertThat(uri, is(locationUri));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("updateHttpChallengeResponse");
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestChallenge(Http01Challenge.TYPE, new Http01Challenge());

        Challenge challenge = client.restoreChallenge(locationUri);

        assertThat(challenge.getStatus(), is(Status.VALID));
        assertThat(challenge.getLocation(), is(locationUri));
    }

    /**
     * Test that a certificate can be requested.
     */
    @Test
    public void testRequestCertificate() throws AcmeException, IOException {
        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(registration.getKeyPair(), is(sameInstance(accountKeyPair)));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URI getLocation() throws AcmeException {
                return locationUri;
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.NEW_CERT, resourceUri);

        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");
        URI certUri = client.requestCertificate(testRegistration, csr);

        assertThat(certUri, is(locationUri));
    }

    /**
     * Test that a certificate can be downloaded.
     */
    @Test
    public void testDownloadCertificate() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();

        Connection connection = new DummyConnection() {
            @Override
            public int sendRequest(URI uri) throws AcmeException {
                assertThat(uri, is(locationUri));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public X509Certificate readCertificate() throws AcmeException {
                return originalCert;
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        X509Certificate downloadedCert = client.downloadCertificate(locationUri);
        assertThat(downloadedCert, is(sameInstance(originalCert)));
    }

    /**
     * Test that a certificate can be revoked.
     */
    @Test
    public void testRevokeCertificate() throws AcmeException, IOException {
        final X509Certificate cert = TestUtils.createCertificate();

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Registration registration) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("revokeCertificateRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(registration, is(sameInstance(testRegistration)));
                return HttpURLConnection.HTTP_OK;
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.REVOKE_CERT, resourceUri);

        client.revokeCertificate(testRegistration, cert);
    }

    /**
     * Extends the {@link AbstractAcmeClient} to be tested, and implements the abstract
     * methods with a simple implementation specially made for testing purposes.
     */
    public static class TestableAbstractAcmeClient extends AbstractAcmeClient {
        private final Map<Resource, URI> resourceMap = new HashMap<>();
        private final Map<String, Challenge> challengeMap = new HashMap<>();
        private final Connection connection;
        private boolean connected = false;

        public TestableAbstractAcmeClient(Connection connection) {
            this.connection = connection;
        }

        /**
         * Register a {@link Resource} mapping.
         *
         * @param r
         *            {@link Resource} to be mapped
         * @param u
         *            {@link URI} to be returned
         */
        public void putTestResource(Resource r, URI u) {
            resourceMap.put(r, u);
        }

        /**
         * Register a {@link Challenge}. For the sake of simplicity,
         * {@link #createChallenge(Map)} will always return the same {@link Challenge}
         * instance in this test suite.
         *
         * @param s
         *            Challenge type
         * @param c
         *            {@link Challenge} instance.
         */
        public void putTestChallenge(String s, Challenge c) {
            challengeMap.put(s, c);
        }

        @Override
        protected URI resourceUri(Resource resource) throws AcmeException {
            if (resourceMap.isEmpty()) {
                fail("Unexpected invocation of resourceUri()");
            }
            URI resUri = resourceMap.get(resource);
            if (resUri == null) {
                fail("Unexpected invocation of resourceUri() with resource " + resource.name());
            }
            return resUri;
        }

        @Override
        protected Challenge createChallenge(Map<String, Object> data) {
            if (challengeMap.isEmpty()) {
                fail("Unexpected invocation of createChallenge()");
            }
            Challenge challenge = challengeMap.get(data.get("type"));
            if (challenge == null) {
                challenge = new GenericChallenge();
            }
            challenge.unmarshall(data);
            return challenge;
        }

        @Override
        protected Connection createConnection() {
            if (connected) {
                fail("createConnection() invoked twice");
            }
            connected = true;
            return connection;
        }
    }

}
