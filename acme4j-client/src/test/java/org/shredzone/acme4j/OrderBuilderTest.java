/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
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
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;

import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link OrderBuilder}.
 */
public class OrderBuilderTest {

    private URL resourceUrl  = url("http://example.com/acme/resource");
    private URL locationUrl  = url(TestUtils.ACCOUNT_URL);

    /**
     * Test that a new {@link Order} can be created.
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testOrderCertificate() throws Exception {
        Instant notBefore = parseTimestamp("2016-01-01T00:00:00Z");
        Instant notAfter = parseTimestamp("2016-01-08T00:00:00Z");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("requestOrderRequest").toString()));
                assertThat(login, is(notNullValue()));
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

        Login login = provider.createLogin();

        provider.putTestResource(Resource.NEW_ORDER, resourceUrl);

        Account account = new Account(login);
        Order order = account.newOrder()
                        .domains("example.com", "www.example.com")
                        .domain("example.org")
                        .domains(Arrays.asList("m.example.com", "m.example.org"))
                        .identifier(Identifier.dns("d.example.com"))
                        .identifiers(Arrays.asList(
                                    Identifier.dns("d2.example.com"),
                                    Identifier.ip(InetAddress.getByName("192.168.1.2"))))
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .create();

        assertThat(order.getDomains(), containsInAnyOrder(
                        "example.com", "www.example.com",
                        "example.org",
                        "m.example.com", "m.example.org",
                        "d.example.com",
                        "d2.example.com"));
        assertThat(order.getIdentifiers(), containsInAnyOrder(
                        Identifier.dns("example.com"),
                        Identifier.dns("www.example.com"),
                        Identifier.dns("example.org"),
                        Identifier.dns("m.example.com"),
                        Identifier.dns("m.example.org"),
                        Identifier.dns("d.example.com"),
                        Identifier.dns("d2.example.com"),
                        Identifier.ip(InetAddress.getByName("192.168.1.2"))));
        assertThat(order.getNotBefore(), is(parseTimestamp("2016-01-01T00:10:00Z")));
        assertThat(order.getNotAfter(), is(parseTimestamp("2016-01-08T00:10:00Z")));
        assertThat(order.getExpires(), is(parseTimestamp("2016-01-10T00:00:00Z")));
        assertThat(order.getStatus(), is(Status.PENDING));
        assertThat(order.getLocation(), is(locationUrl));
        assertThat(order.getAuthorizations(), is(notNullValue()));
        assertThat(order.getAuthorizations().size(), is(2));

        provider.close();
    }

}
