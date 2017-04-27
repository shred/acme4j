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
import static org.shredzone.acme4j.util.AcmeUtils.parseTimestamp;
import static org.shredzone.acme4j.util.TestUtils.*;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.util.JSON;
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link Order}.
 */
public class OrderTest {

    private URL locationUrl = url("http://example.com/acme/order/1234");

    /**
     * Test that order is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        byte[] csr = TestUtils.getResourceAsByteArray("/csr.der");

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }
        };

        Session session = provider.createSession();

        Order order = new Order(session, locationUrl);
        order.update();

        assertThat(order.getStatus(), is(Status.PENDING));
        assertThat(order.getExpires(), is(parseTimestamp("2015-03-01T14:09:00Z")));
        assertThat(order.getLocation(), is(locationUrl));

        assertThat(order.getNotBefore(), is(parseTimestamp("2016-01-01T00:00:00Z")));
        assertThat(order.getNotAfter(), is(parseTimestamp("2016-01-08T00:00:00Z")));
        assertThat(order.getCertificate().getLocation(), is(url("https://example.com/acme/cert/1234")));
        assertThat(order.getCsr(), is(csr));

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
            public void sendRequest(URL url, Session session) {
                requestWasSent.set(true);
                assertThat(url, is(locationUrl));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }
        };

        Session session = provider.createSession();

        Order order = new Order(session, locationUrl);

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

}
