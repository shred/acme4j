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
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.Map;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.ClaimBuilder;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Registration}.
 *
 * @author Richard "Shred" Körber
 */
public class RegistrationTest {

    private URI resourceUri  = URI.create("http://example.com/acme/resource");
    private URI locationUri  = URI.create("http://example.com/acme/registration");
    private URI agreementUri = URI.create("http://example.com/agreement.pdf");

    /**
     * Test getters. Make sure object cannot be modified.
     */
    @Test
    public void testGetters() throws IOException, URISyntaxException {
        Session session = TestUtils.session();
        Registration registration = new Registration(session, locationUri);

        assertThat(registration.getAgreement(), is(nullValue()));
        assertThat(registration.getContacts(), is(empty()));

        try {
            registration.getContacts().add(new URI("mailto:foo@example.com"));
            fail("could modify contacts list");
        } catch (UnsupportedOperationException ex) {
            // expected
        }
    }

    /**
     * Test that a registration can be updated.
     */
    @Test
    public void testUpdateRegistration() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("updateRegistration")));
                assertThat(session, is(notNullValue()));
                return HttpURLConnection.HTTP_ACCEPTED;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("updateRegistrationResponse");
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
        registration.update();

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(registration.getContacts(), hasSize(1));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));

        provider.close();
    }

    /**
     * Test that a new {@link Authorization} can be created.
     */
    @Test
    public void testAuthorizeDomain() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("newAuthorizationRequest")));
                assertThat(session, is(notNullValue()));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public Map<String, Object> readJsonResponse() {
                return getJsonAsMap("newAuthorizationResponse");
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
     * Test that a certificate can be requested.
     */
    @Test
    public void testRequestCertificate() throws AcmeException, IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(resourceUri));
                assertThat(claims.toString(), sameJSONAs(getJson("requestCertificateRequest")));
                assertThat(session, is(notNullValue()));
                return HttpURLConnection.HTTP_CREATED;
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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(locationUri));
                assertThat(session, is(notNullValue()));
                assertThat(session.getKeyPair(), is(sameInstance(newKeyPair))); // registration has new KeyPair!

                Map<String, Object> claimMap = claims.toMap();
                assertThat(claimMap.get("resource"), is((Object) "reg"));
                assertThat(claimMap.get("rollover"), not(nullValue()));

                try {
                    StringBuilder expectedPayload = new StringBuilder();
                    expectedPayload.append('{');
                    expectedPayload.append("\"resource\":\"reg\",");
                    expectedPayload.append("\"newKey\":\"").append(TestUtils.D_THUMBPRINT).append("\"");
                    expectedPayload.append("}");

                    String rollover = (String) claimMap.get("rollover");
                    JsonWebSignature jws = (JsonWebSignature) JsonWebSignature.fromCompactSerialization(rollover);
                    jws.setKey(oldKeyPair.getPublic()); // signed with the old KeyPair!
                    assertThat(jws.getPayload(), sameJSONAs(expectedPayload.toString()));
                } catch (JoseException ex) {
                    throw new AcmeProtocolException("Bad rollover", ex);
                }

                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }
        };

        Session session = new Session(new URI(TestUtils.ACME_SERVER_URI), oldKeyPair) {
            @Override
            public AcmeProvider provider() {
                return provider;
            };
        };

        Registration registration = new Registration(session, locationUri);
        registration.changeKey(newKeyPair);
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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                Map<String, Object> claimMap = claims.toMap();
                assertThat(claimMap.get("resource"), is((Object) "reg"));
                assertThat(claimMap.get("status"), is((Object) "deactivated"));
                assertThat(uri, is(locationUri));
                assertThat(session, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
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
            public int sendSignedRequest(URI uri, ClaimBuilder claims, Session session) {
                assertThat(uri, is(locationUri));
                assertThat(claims.toString(), sameJSONAs(getJson("modifyRegistration")));
                assertThat(session, is(notNullValue()));
                return HttpURLConnection.HTTP_ACCEPTED;
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

        registration.modify()
                .setAgreement(agreementUri)
                .addContact("mailto:foo2@example.com")
                .commit();

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getAgreement(), is(agreementUri));
        assertThat(registration.getContacts().size(), is(1));
        assertThat(registration.getContacts().get(0), is(URI.create("mailto:foo2@example.com")));

        provider.close();
    }

}
