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
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Challenge.Status;
import org.shredzone.acme4j.challenge.DnsChallenge;
import org.shredzone.acme4j.challenge.GenericChallenge;
import org.shredzone.acme4j.challenge.HttpChallenge;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.connector.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link AbstractAcmeClient}.
 *
 * @author Richard "Shred" Körber
 */
public class AbstractAcmeClientTest {

    private Account testAccount;
    private URI resourceUri;
    private URI locationUri;
    private URI agreementUri;

    @Before
    public void setup() throws IOException, URISyntaxException {
        resourceUri = new URI("https://example.com/acme/some-resource");
        locationUri = new URI("https://example.com/acme/some-location");
        agreementUri = new URI("http://example.com/agreement.pdf");
        testAccount = new Account(TestUtils.createKeyPair());
    }

    /**
     * Test that a new {@link Registration} can be registered.
     */
    @Test
    public void testNewRegistration() throws AcmeException {
        Registration registration = new Registration();
        registration.addContact("mailto:foo@example.com");

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newRegistration")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
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

        client.newRegistration(testAccount, registration);

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
    }

    /**
     * Test that a {@link Registration} can be modified.
     */
    @Test
    public void testModifyRegistration() throws AcmeException {
        Registration registration = new Registration();
        registration.setAgreement(agreementUri);
        registration.addContact("mailto:foo2@example.com");
        registration.setLocation(locationUri);

        Connection connection = new DummyConnection() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("modifyRegistration")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
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

        client.modifyRegistration(testAccount, registration);

        assertThat(registration.getLocation(), is(locationUri));
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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newAuthorizationRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
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

        HttpChallenge httpChallenge = new HttpChallenge();
        DnsChallenge dnsChallenge = new DnsChallenge();

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.NEW_AUTHZ, resourceUri);
        client.putTestChallenge("http-01", httpChallenge);
        client.putTestChallenge("dns-01", dnsChallenge);

        client.newAuthorization(testAccount, auth);

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is("pending"));
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

        HttpChallenge httpChallenge = new HttpChallenge();
        DnsChallenge dnsChallenge = new DnsChallenge();

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestChallenge("http-01", httpChallenge);
        client.putTestChallenge("dns-01", dnsChallenge);

        client.updateAuthorization(auth);

        assertThat(auth.getDomain(), is("example.org"));
        assertThat(auth.getStatus(), is("valid"));
        assertThat(auth.getExpires(), is("2015-03-01"));
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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("triggerHttpChallengeRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() throws AcmeException {
                return getJsonAsMap("triggerHttpChallengeResponse");
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);

        Challenge challenge = new HttpChallenge();
        challenge.unmarshall(getJsonAsMap("triggerHttpChallenge"));
        challenge.authorize(testAccount);

        client.triggerChallenge(testAccount, challenge);

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

        Challenge challenge = new HttpChallenge();
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
        client.putTestChallenge(HttpChallenge.TYPE, new HttpChallenge());

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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
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
        URI certUri = client.requestCertificate(testAccount, csr);

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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session, Account account) throws AcmeException {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("revokeCertificateRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(account, is(sameInstance(testAccount)));
                return HttpURLConnection.HTTP_OK;
            }
        };

        TestableAbstractAcmeClient client = new TestableAbstractAcmeClient(connection);
        client.putTestResource(Resource.REVOKE_CERT, resourceUri);

        client.revokeCertificate(testAccount, cert);
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
         * {@link #createChallenge(String)} will always return the same {@link Challenge}
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
        protected Challenge createChallenge(String type) {
            if (challengeMap.isEmpty()) {
                fail("Unexpected invocation of createChallenge()");
            }
            Challenge challenge = challengeMap.get(type);
            return (challenge != null ? challenge : new GenericChallenge());
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
