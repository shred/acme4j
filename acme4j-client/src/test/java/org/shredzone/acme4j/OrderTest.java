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

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.exception.AcmeNotSupportedException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Order}.
 */
public class OrderTest {

    private final URL locationUrl = url("http://example.com/acme/order/1234");
    private final URL finalizeUrl = url("https://example.com/acme/acct/1/order/1/finalize");

    /**
     * Test that order is properly updated.
     */
    @Test
    public void testUpdate() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message).isNotNull();
            }
        };

        var login = provider.createLogin();

        var order = new Order(login, locationUrl);
        order.update();

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(order.getStatus()).isEqualTo(Status.PENDING);
            softly.assertThat(order.getExpires().orElseThrow()).isEqualTo("2015-03-01T14:09:00Z");
            softly.assertThat(order.getLocation()).isEqualTo(locationUrl);

            softly.assertThat(order.getIdentifiers()).containsExactlyInAnyOrder(
                    Identifier.dns("example.com"),
                    Identifier.dns("www.example.com"));
            softly.assertThat(order.getNotBefore().orElseThrow())
                    .isEqualTo("2016-01-01T00:00:00Z");
            softly.assertThat(order.getNotAfter().orElseThrow())
                    .isEqualTo("2016-01-08T00:00:00Z");
            softly.assertThat(order.getCertificate().getLocation())
                    .isEqualTo(url("https://example.com/acme/cert/1234"));
            softly.assertThat(order.getFinalizeLocation()).isEqualTo(finalizeUrl);

            softly.assertThat(order.isAutoRenewing()).isFalse();
            softly.assertThatExceptionOfType(AcmeNotSupportedException.class)
                    .isThrownBy(order::getAutoRenewalStartDate);
            softly.assertThatExceptionOfType(AcmeNotSupportedException.class)
                    .isThrownBy(order::getAutoRenewalEndDate);
            softly.assertThatExceptionOfType(AcmeNotSupportedException.class)
                    .isThrownBy(order::getAutoRenewalLifetime);
            softly.assertThatExceptionOfType(AcmeNotSupportedException.class)
                    .isThrownBy(order::getAutoRenewalLifetimeAdjust);
            softly.assertThatExceptionOfType(AcmeNotSupportedException.class)
                    .isThrownBy(order::isAutoRenewalGetEnabled);

            softly.assertThat(order.getError()).isNotEmpty();
            softly.assertThat(order.getError().orElseThrow().getType())
                    .isEqualTo(URI.create("urn:ietf:params:acme:error:connection"));
            softly.assertThat(order.getError().flatMap(Problem::getDetail).orElseThrow())
                    .isEqualTo("connection refused");

            var auths = order.getAuthorizations();
            softly.assertThat(auths).hasSize(2);
            softly.assertThat(auths.stream())
                    .map(Authorization::getLocation)
                    .containsExactlyInAnyOrder(
                            url("https://example.com/acme/authz/1234"),
                            url("https://example.com/acme/authz/2345"));
        }

        provider.close();
    }

    /**
     * Test lazy loading.
     */
    @Test
    public void testLazyLoading() throws Exception {
        var requestWasSent = new AtomicBoolean(false);

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                requestWasSent.set(true);
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message).isNotNull();
            }
        };

        var login = provider.createLogin();

        var order = new Order(login, locationUrl);

        try (var softly = new AutoCloseableSoftAssertions()) {
            // Lazy loading
            softly.assertThat(requestWasSent).isFalse();
            softly.assertThat(order.getCertificate().getLocation())
                    .isEqualTo(url("https://example.com/acme/cert/1234"));
            softly.assertThat(requestWasSent).isTrue();

            // Subsequent queries do not trigger another load
            requestWasSent.set(false);
            softly.assertThat(order.getCertificate().getLocation())
                    .isEqualTo(url("https://example.com/acme/cert/1234"));
            softly.assertThat(order.getStatus()).isEqualTo(Status.PENDING);
            softly.assertThat(order.getExpires().orElseThrow()).isEqualTo("2015-03-01T14:09:00Z");
            softly.assertThat(requestWasSent).isFalse();
        }

        provider.close();
    }

    /**
     * Test that order is properly finalized.
     */
    @Test
    public void testFinalize() throws Exception {
        var csr = TestUtils.getResourceAsByteArray("/csr.der");

        var provider = new TestableConnectionProvider() {
            private boolean isFinalized = false;

            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(finalizeUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("finalizeRequest").toString());
                assertThat(login).isNotNull();
                isFinalized = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON(isFinalized ? "finalizeResponse" : "updateOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message).isNotNull();
            }
        };

        var login = provider.createLogin();

        var order = new Order(login, locationUrl);
        order.execute(csr);

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(order.getStatus()).isEqualTo(Status.VALID);
            softly.assertThat(order.getExpires().orElseThrow()).isEqualTo("2015-03-01T14:09:00Z");
            softly.assertThat(order.getLocation()).isEqualTo(locationUrl);

            softly.assertThat(order.getIdentifiers()).containsExactlyInAnyOrder(
                    Identifier.dns("example.com"),
                    Identifier.dns("www.example.com"));
            softly.assertThat(order.getNotBefore().orElseThrow())
                    .isEqualTo("2016-01-01T00:00:00Z");
            softly.assertThat(order.getNotAfter().orElseThrow())
                    .isEqualTo("2016-01-08T00:00:00Z");
            softly.assertThat(order.getCertificate().getLocation())
                    .isEqualTo(url("https://example.com/acme/cert/1234"));
            softly.assertThat(order.getAutoRenewalCertificate()).isEmpty();
            softly.assertThat(order.getFinalizeLocation()).isEqualTo(finalizeUrl);

            var auths = order.getAuthorizations();
            softly.assertThat(auths).hasSize(2);
            softly.assertThat(auths.stream())
                    .map(Authorization::getLocation)
                    .containsExactlyInAnyOrder(
                            url("https://example.com/acme/authz/1234"),
                            url("https://example.com/acme/authz/2345"));
        }

        provider.close();
    }

    /**
     * Test that order is properly updated.
     */
    @Test
    public void testAutoRenewUpdate() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("updateAutoRenewOrderResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message).isNotNull();
            }
        };

        provider.putMetadata("auto-renewal", JSON.empty());

        var login = provider.createLogin();

        var order = new Order(login, locationUrl);
        order.update();

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(order.isAutoRenewing()).isTrue();
            softly.assertThat(order.getAutoRenewalStartDate().orElseThrow())
                    .isEqualTo("2016-01-01T00:00:00Z");
            softly.assertThat(order.getAutoRenewalEndDate())
                    .isEqualTo("2017-01-01T00:00:00Z");
            softly.assertThat(order.getAutoRenewalLifetime())
                    .isEqualTo(Duration.ofHours(168));
            softly.assertThat(order.getAutoRenewalLifetimeAdjust().orElseThrow())
                    .isEqualTo(Duration.ofDays(6));
            softly.assertThat(order.getNotBefore()).isEmpty();
            softly.assertThat(order.getNotAfter()).isEmpty();
            softly.assertThat(order.isAutoRenewalGetEnabled()).isTrue();
        }

        provider.close();
    }

    /**
     * Test that auto-renew order is properly finalized.
     */
    @Test
    public void testAutoRenewFinalize() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedPostAsGetRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("finalizeAutoRenewResponse");
            }

            @Override
            public void handleRetryAfter(String message) {
                assertThat(message).isNotNull();
            }
        };

        var login = provider.createLogin();
        var order = login.bindOrder(locationUrl);

        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThatIllegalStateException()
                    .isThrownBy(order::getCertificate);
            softly.assertThat(order.getAutoRenewalCertificate().orElseThrow().getLocation())
                    .isEqualTo(url("https://example.com/acme/cert/1234"));
            softly.assertThat(order.isAutoRenewing()).isTrue();
            softly.assertThat(order.getAutoRenewalStartDate().orElseThrow())
                    .isEqualTo("2018-01-01T00:00:00Z");
            softly.assertThat(order.getAutoRenewalEndDate())
                    .isEqualTo("2019-01-01T00:00:00Z");
            softly.assertThat(order.getAutoRenewalLifetime())
                    .isEqualTo(Duration.ofHours(168));
            softly.assertThat(order.getAutoRenewalLifetimeAdjust().orElseThrow())
                    .isEqualTo(Duration.ofDays(6));
            softly.assertThat(order.getNotBefore()).isEmpty();
            softly.assertThat(order.getNotAfter()).isEmpty();
            softly.assertThat(order.isAutoRenewalGetEnabled()).isTrue();
        }

        provider.close();
    }

    /**
     * Test that auto-renew order is properly canceled.
     */
    @Test
    public void testCancel() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                var json = claims.toJSON();
                assertThat(json.get("status").asString()).isEqualTo("canceled");
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("canceledOrderResponse");
            }
        };

        provider.putMetadata("auto-renewal", JSON.empty());

        var login = provider.createLogin();

        var order = new Order(login, locationUrl);
        order.cancelAutoRenewal();

        assertThat(order.getStatus()).isEqualTo(Status.CANCELED);

        provider.close();
    }

}
