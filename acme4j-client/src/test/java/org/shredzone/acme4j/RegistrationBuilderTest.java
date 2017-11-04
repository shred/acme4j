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
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link RegistrationBuilder}.
 */
public class RegistrationBuilderTest {

    private URL resourceUrl  = url("http://example.com/acme/resource");
    private URL locationUrl  = url("http://example.com/acme/registration");
    private URI agreementUri = URI.create("http://example.com/agreement.pdf");;

    /**
     * Test if a new registration can be created.
     */
    @Test
    public void testRegistration() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJson("newRegistration")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_CREATED));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }

            @Override
            public URI getLinkAsURI(String relation) {
                switch(relation) {
                    case "terms-of-service": return agreementUri;
                    default: return null;
                }
            }
        };

        provider.putTestResource(Resource.NEW_REG, resourceUrl);

        RegistrationBuilder builder = new RegistrationBuilder();
        builder.addContact("mailto:foo@example.com");

        Registration registration = builder.create(provider.createSession());

        assertThat(registration.getLocation(), is(locationUrl));
        assertThat(registration.getAgreement(), is(agreementUri));

        provider.close();
    }

}
