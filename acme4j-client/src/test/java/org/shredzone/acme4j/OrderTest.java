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
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Order}.
 */
public class OrderTest {

    private URL locationUrl = url("http://example.com/acme/order/1234");
    private URL finalizeUrl = url("https://example.com/acme/acct/1/order/1/finalize");

    /**
     * Test that order is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message, not(nullValue()));
            }
        };

        Login login = provider.createLogin();

        Order order = new Order(login, locationUrl);
        order.update();

        assertThat(order.getStatus(), is(Status.PENDING));
        assertThat(order.getExpires(), is(parseTimestamp("2015-03-01T14:09:00Z")));
        assertThat(order.getLocation(), is(locationUrl));

        assertThat(order.getIdentifiers(), containsInAnyOrder(
                    Identifier.dns("example.com"),
                    Identifier.dns("www.example.com")));
        assertThat(order.getNotBefore(), is(parseTimestamp("2016-01-01T00:00:00Z")));
        assertThat(order.getNotAfter(), is(parseTimestamp("2016-01-08T00:00:00Z")));
        assertThat(order.getCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(order.getFinalizeLocation(), is(finalizeUrl));

        assertThat(order.isRecurrent(), is(false));
        assertThat(order.getRecurrentStart(), is(nullValue()));
        assertThat(order.getRecurrentEnd(), is(nullValue()));
        assertThat(order.getRecurrentCertificateValidity(), is(nullValue()));
        assertThat(order.getRecurrentCertificatePredate(), is(nullValue()));
        assertThat(order.isRecurrentGetEnabled(), is(false));

        assertThat(order.getError(), is(notNullValue()));
        assertThat(order.getError().getType(), is(URI.create("urn:ietf:params:acme:error:connection")));
        assertThat(order.getError().getDetail(), is("connection refused"));

        List<Authorization> auths = order.getAuthorizations();
        assertThat(auths.size(), is(2));
        assertThat(auths.stream().map(Authorization::getLocation)::iterator,
                containsInAnyOrder(
                    url("https://example.com/acme/authz/1234"),
                    url("https://example.com/acme/authz/2345")));

        provider.close();
    }

    /**
     * Test lazy loading.
     */
    @Test
    public void testLazyLoading() throws Exception {
        final AtomicBoolean requestWasSent = new AtomicBoolean(false);

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                requestWasSent.set(true);
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message, not(nullValue()));
            }
        };

        Login login = provider.createLogin();

        Order order = new Order(login, locationUrl);

        // Lazy loading
        assertThat(requestWasSent.get(), is(false));
        assertThat(order.getCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(requestWasSent.get(), is(true));

        // Subsequent queries do not trigger another load
        requestWasSent.set(false);
        assertThat(order.getCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(order.getStatus(), is(Status.PENDING));
        assertThat(order.getExpires(), is(parseTimestamp("2015-03-01T14:09:00Z")));
        assertThat(requestWasSent.get(), is(false));

        provider.close();
    }

    /**
     * Test that order is properly finalized.
     */
    @Test
    public void testFinalize() throws Exception {
        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean isFinalized = false;

            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url, is(finalizeUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("finalizeRequest").toString()));
                assertThat(login, is(notNullValue()));
                isFinalized = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON(isFinalized ? "finalizeResponse" : "updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message, not(nullValue()));
            }
        };

        Login login = provider.createLogin();

        Order order = new Order(login, locationUrl);
        order.execute(csr);

        assertThat(order.getStatus(), is(Status.VALID));
        assertThat(order.getExpires(), is(parseTimestamp("2015-03-01T14:09:00Z")));
        assertThat(order.getLocation(), is(locationUrl));

        assertThat(order.getIdentifiers(), containsInAnyOrder(
                        Identifier.dns("example.com"),
                        Identifier.dns("www.example.com")));
        assertThat(order.getNotBefore(), is(parseTimestamp("2016-01-01T00:00:00Z")));
        assertThat(order.getNotAfter(), is(parseTimestamp("2016-01-08T00:00:00Z")));
        assertThat(order.getCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(order.getStarCertificate(), is(nullValue()));
        assertThat(order.getFinalizeLocation(), is(finalizeUrl));

        List<Authorization> auths = order.getAuthorizations();
        assertThat(auths.size(), is(2));
        assertThat(auths.stream().map(Authorization::getLocation)::iterator,
                containsInAnyOrder(
                    url("https://example.com/acme/authz/1234"),
                    url("https://example.com/acme/authz/2345")));

        provider.close();
    }

    /**
     * Test that order is properly updated.
     */
    @Test
    public void testRecurrentUpdate() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateRecurrentOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message, not(nullValue()));
            }
        };

        provider.putMetadata("star-enabled", true);

        Login login = provider.createLogin();

        Order order = new Order(login, locationUrl);
        order.update();

        assertThat(order.isRecurrent(), is(true));
        assertThat(order.getRecurrentStart(), is(parseTimestamp("2016-01-01T00:00:00Z")));
        assertThat(order.getRecurrentEnd(), is(parseTimestamp("2017-01-01T00:00:00Z")));
        assertThat(order.getRecurrentCertificateValidity(), is(Duration.ofHours(168)));
        assertThat(order.getRecurrentCertificatePredate(), is(Duration.ofDays(6)));
        assertThat(order.getNotBefore(), is(nullValue()));
        assertThat(order.getNotAfter(), is(nullValue()));
        assertThat(order.isRecurrentGetEnabled(), is(true));

        provider.close();
    }

    /**
     * Test that recurrent order is properly finalized.
     */
    @Test
    public void testRecurrentFinalize() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url, is(locationUrl));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("finalizeRecurrentResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message, not(nullValue()));
            }
        };

        Login login = provider.createLogin();
        Order order = login.bindOrder(locationUrl);

        assertThat(order.getCertificate(), is(nullValue()));
        assertThat(order.getStarCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(order.isRecurrent(), is(true));
        assertThat(order.getRecurrentStart(), is(parseTimestamp("2018-01-01T00:00:00Z")));
        assertThat(order.getRecurrentEnd(), is(parseTimestamp("2019-01-01T00:00:00Z")));
        assertThat(order.getRecurrentCertificateValidity(), is(Duration.ofHours(168)));
        assertThat(order.getRecurrentCertificatePredate(), is(Duration.ofDays(6)));
        assertThat(order.getNotBefore(), is(nullValue()));
        assertThat(order.getNotAfter(), is(nullValue()));
        assertThat(order.isRecurrentGetEnabled(), is(true));

        provider.close();
    }

    /**
     * Test that recurrent order is properly canceled.
     */
    @Test
    public void testCancel() throws Exception {
        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                JSON json = claims.toJSON();
                assertThat(json.get("status").asString(), is("canceled"));
                assertThat(url, is(locationUrl));
                assertThat(login, is(notNullValue()));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("canceledOrderResponse");
            }
        };

        provider.putMetadata("star-enabled", true);

        Login login = provider.createLogin();

        Order order = new Order(login, locationUrl);
        order.cancelRecurrent();

        assertThat(order.getStatus(), is(Status.CANCELED));

        provider.close();
    }

}
