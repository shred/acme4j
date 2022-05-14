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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link OrderBuilder}.
 */
public class OrderBuilderTest {

    private final URL resourceUrl  = url("http://example.com/acme/resource");
    private final URL locationUrl  = url(TestUtils.ACCOUNT_URL);

    /**
     * Test that a new {@link Order} can be created.
     */
    @Test
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
        assertThat(order.isAutoRenewing(), is(false));
        assertThat(order.getAutoRenewalStartDate(), is(nullValue()));
        assertThat(order.getAutoRenewalEndDate(), is(nullValue()));
        assertThat(order.getAutoRenewalLifetime(), is(nullValue()));
        assertThat(order.getAutoRenewalLifetimeAdjust(), is(nullValue()));
        assertThat(order.isAutoRenewalGetEnabled(), is(false));
        assertThat(order.getLocation(), is(locationUrl));
        assertThat(order.getAuthorizations(), is(notNullValue()));
        assertThat(order.getAuthorizations().size(), is(2));

        provider.close();
    }

    /**
     * Test that a new auto-renewal {@link Order} can be created.
     */
    @Test
    public void testAutoRenewOrderCertificate() throws Exception {
        Instant autoRenewStart = parseTimestamp("2018-01-01T00:00:00Z");
        Instant autoRenewEnd = parseTimestamp("2019-01-01T00:00:00Z");
        Duration validity = Duration.ofDays(7);
        Duration predate = Duration.ofDays(6);

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("requestAutoRenewOrderRequest").toString()));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_CREATED;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("requestAutoRenewOrderResponse");
            }

            @Override
            public URL getLocation() {
                return locationUrl;
            }
        };

        Login login = provider.createLogin();

        provider.putMetadata("auto-renewal", JSON.empty());
        provider.putTestResource(Resource.NEW_ORDER, resourceUrl);

        Account account = new Account(login);
        Order order = account.newOrder()
                        .domain("example.org")
                        .autoRenewal()
                        .autoRenewalStart(autoRenewStart)
                        .autoRenewalEnd(autoRenewEnd)
                        .autoRenewalLifetime(validity)
                        .autoRenewalLifetimeAdjust(predate)
                        .autoRenewalEnableGet()
                        .create();

        assertThat(order.getIdentifiers(), containsInAnyOrder(Identifier.dns("example.org")));
        assertThat(order.getNotBefore(), is(nullValue()));
        assertThat(order.getNotAfter(), is(nullValue()));
        assertThat(order.isAutoRenewing(), is(true));
        assertThat(order.getAutoRenewalStartDate(), is(autoRenewStart));
        assertThat(order.getAutoRenewalEndDate(), is(autoRenewEnd));
        assertThat(order.getAutoRenewalLifetime(), is(validity));
        assertThat(order.getAutoRenewalLifetimeAdjust(), is(predate));
        assertThat(order.isAutoRenewalGetEnabled(), is(true));
        assertThat(order.getLocation(), is(locationUrl));

        provider.close();
    }

    /**
     * Test that an auto-renewal {@link Order} cannot be created if unsupported by the CA.
     */
    @Test
    public void testAutoRenewOrderCertificateFails() throws Exception {
        assertThrows(AcmeException.class, () -> {
            TestableConnectionProvider provider = new TestableConnectionProvider();
            provider.putTestResource(Resource.NEW_ORDER, resourceUrl);

            Login login = provider.createLogin();

            Account account = new Account(login);
            account.newOrder()
                            .domain("example.org")
                            .autoRenewal()
                            .create();

            provider.close();
        });
    }

    /**
     * Test that auto-renew and notBefore/notAfter cannot be mixed.
     */
    @Test
    public void testAutoRenewNotMixed() throws Exception {
        Instant someInstant = parseTimestamp("2018-01-01T00:00:00Z");

        TestableConnectionProvider provider = new TestableConnectionProvider();
        Login login = provider.createLogin();

        Account account = new Account(login);

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().autoRenewal();
            ob.notBefore(someInstant);
        }, "accepted notBefore");

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().autoRenewal();
            ob.notAfter(someInstant);
        }, "accepted notAfter");

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().notBefore(someInstant);
            ob.autoRenewal();
        }, "accepted autoRenewal");

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().notBefore(someInstant);
            ob.autoRenewalStart(someInstant);
        }, "accepted autoRenewalStart");

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().notBefore(someInstant);
            ob.autoRenewalEnd(someInstant);
        }, "accepted autoRenewalEnd");

        assertThrows(IllegalArgumentException.class, () -> {
            OrderBuilder ob = account.newOrder().notBefore(someInstant);
            ob.autoRenewalLifetime(Duration.ofDays(7));
        }, "accepted autoRenewalLifetime");

        provider.close();
    }

}
