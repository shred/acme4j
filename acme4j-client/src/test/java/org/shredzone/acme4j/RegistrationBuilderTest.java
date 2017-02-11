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
import java.net.URI;

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

    private URI resourceUri  = URI.create("http://example.com/acme/resource");;
    private URI locationUri  = URI.create("http://example.com/acme/registration");;

    /**
     * Test if a new registration can be created.
     */
    @Test
    public void testRegistration() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean isUpdate;

            @Override
            public void sendSignedRequest(URI uri, JSONBuilder claims, Session session) {
                assertThat(session, is(notNullValue()));
                if (resourceUri.equals(uri)) {
                    isUpdate = false;
                    assertThat(claims.toString(), sameJSONAs(getJson("newRegistration")));
                } else if (locationUri.equals(uri)) {
                    isUpdate = true;
                } else {
                    fail("bad URI");
                }
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                if (isUpdate) {
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_ACCEPTED));
                    return HttpURLConnection.HTTP_ACCEPTED;
                } else {
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED));
                    return HttpURLConnection.HTTP_CREATED;
                }
            }

            @Override
            public URI getLocation() {
                return locationUri;
            }

            @Override
            public JSON readJsonResponse() {
                assertThat(isUpdate, is(true));
                return getJsonAsObject("newRegistrationResponse");
            }
        };

        provider.putTestResource(Resource.NEW_REG, resourceUri);

        RegistrationBuilder builder = new RegistrationBuilder();
        builder.addContact("mailto:foo@example.com");
        builder.agreeToTermsOfService();

        Registration registration = builder.create(provider.createSession());

        assertThat(registration.getLocation(), is(locationUri));
        assertThat(registration.getTermsOfServiceAgreed(), is(true));

        provider.close();
    }

}
