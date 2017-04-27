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

import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.JSONBuilder;

/**
 * Unit tests for {@link RegistrationBuilder}.
 */
public class RegistrationBuilderTest {

    private URL resourceUrl = url("http://example.com/acme/resource");
    private URL locationUrl = url("http://example.com/acme/registration");;

    /**
     * Test if a new registration can be created.
     */
    @Test
    public void testRegistration() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean isUpdate;

            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(session, is(notNullValue()));
                assertThat(url, is(locationUrl));
                assertThat(isUpdate, is(false));
                isUpdate = true;
            }

            @Override
            public void sendJwkSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(session, is(notNullValue()));
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("newRegistration").toString()));
                isUpdate = false;
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                if (isUpdate) {
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                    return HttpURLConnection.HTTP_ACCEPTED;
                } else {
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED));
                    return HttpURLConnection.HTTP_CREATED;
                }
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("newRegistrationResponse");
            }
        };

        provider.putTestResource(Resource.NEW_REG, resourceUrl);

        RegistrationBuilder builder = new RegistrationBuilder();
        builder.addContact("mailto:foo@example.com");
        builder.agreeToTermsOfService();

        Session session = provider.createSession();
        Registration registration = builder.create(session);

        assertThat(registration.getLocation(), is(locationUrl));
        assertThat(registration.getTermsOfServiceAgreed(), is(true));
        assertThat(session.getKeyIdentifier(), is(locationUrl.toString()));

        try {
            RegistrationBuilder builder2 = new RegistrationBuilder();
            builder2.agreeToTermsOfService();
            builder2.create(session);
            fail("registered twice on same session");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        provider.close();
    }

}
