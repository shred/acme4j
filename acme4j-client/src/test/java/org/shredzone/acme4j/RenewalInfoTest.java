/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;
import static org.shredzone.acme4j.toolbox.TestUtils.url;

import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Unit test for {@link RenewalInfo}.
 */
public class RenewalInfoTest {

    private final URL locationUrl = url("http://example.com/acme/renewalInfo/1234");
    private final Instant retryAfterInstant = Instant.now().plus(10L, ChronoUnit.DAYS);
    private final Instant startWindow = Instant.parse("2021-01-03T00:00:00Z");
    private final Instant endWindow = Instant.parse("2021-01-07T00:00:00Z");

    @Test
    public void testGetters() throws Exception {
        var provider = new TestableConnectionProvider() {
            @Override
            public int sendRequest(URL url, Session session, ZonedDateTime ifModifiedSince) {
                assertThat(url).isEqualTo(locationUrl);
                assertThat(session).isNotNull();
                assertThat(ifModifiedSince).isNull();
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                return getJSON("renewalInfo");
            }

            @Override
            public Optional<Instant> getRetryAfter() {
                return Optional.of(retryAfterInstant);
            }
        };

        var login = provider.createLogin();

        var renewalInfo = new RenewalInfo(login, locationUrl);
        renewalInfo.update();

        // Check getters
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(renewalInfo.getLocation()).isEqualTo(locationUrl);
            softly.assertThat(renewalInfo.getRecheckAfter())
                    .isNotEmpty()
                    .contains(retryAfterInstant);
            softly.assertThat(renewalInfo.getSuggestedWindowStart())
                    .isEqualTo(startWindow);
            softly.assertThat(renewalInfo.getSuggestedWindowEnd())
                    .isEqualTo(endWindow);
            softly.assertThat(renewalInfo.getExplanation())
                    .isNotEmpty()
                    .contains(url("https://example.com/docs/example-mass-reissuance-event"));
        }

        // Check renewalIsNotRequired
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(renewalInfo.renewalIsNotRequired(startWindow.minusSeconds(1L)))
                    .isTrue();
            softly.assertThat(renewalInfo.renewalIsNotRequired(startWindow))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsNotRequired(endWindow.minusSeconds(1L)))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsNotRequired(endWindow))
                    .isFalse();
        }

        // Check renewalIsRecommended
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(renewalInfo.renewalIsRecommended(startWindow.minusSeconds(1L)))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsRecommended(startWindow))
                    .isTrue();
            softly.assertThat(renewalInfo.renewalIsRecommended(endWindow.minusSeconds(1L)))
                    .isTrue();
            softly.assertThat(renewalInfo.renewalIsRecommended(endWindow))
                    .isFalse();
        }

        // Check renewalIsOverdue
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(renewalInfo.renewalIsOverdue(startWindow.minusSeconds(1L)))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsOverdue(startWindow))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsOverdue(endWindow.minusSeconds(1L)))
                    .isFalse();
            softly.assertThat(renewalInfo.renewalIsOverdue(endWindow))
                    .isTrue();
        }

        // Check getRandomProposal, is empty because end window is in the past
        var proposal = renewalInfo.getRandomProposal(null);
        assertThat(proposal).isEmpty();

        provider.close();
    }

    @Test
    public void testRandomProposal() {
        var login = mock(Login.class);
        var start = Instant.now();
        var end = start.plus(1L, ChronoUnit.DAYS);

        var renewalInfo = new RenewalInfo(login, locationUrl) {
            @Override
            public Instant getSuggestedWindowStart() {
                return start;
            }

            @Override
            public Instant getSuggestedWindowEnd() {
                return end;
            }
        };

        var noFreq = renewalInfo.getRandomProposal(null);
        assertThat(noFreq).isNotEmpty();
        assertThat(noFreq.get()).isBetween(start, end);

        var oneHour = renewalInfo.getRandomProposal(Duration.ofHours(1L));
        assertThat(oneHour).isNotEmpty();
        assertThat(oneHour.get()).isBetween(start, end.minus(1L, ChronoUnit.HOURS));

        var twoDays = renewalInfo.getRandomProposal(Duration.ofDays(2L));
        assertThat(twoDays).isEmpty();
    }

    @Test
    public void testDateAssertion() {
        var login = mock(Login.class);
        var start = Instant.now();
        var end = start.minusSeconds(1L);  // end before start

        var renewalInfo = new RenewalInfo(login, locationUrl) {
            @Override
            public Instant getSuggestedWindowStart() {
                return start;
            }

            @Override
            public Instant getSuggestedWindowEnd() {
                return end;
            }
        };

        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> renewalInfo.renewalIsRecommended(start));
    }

}
