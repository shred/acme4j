/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2025 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.challenge;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link DnsAccount01Challenge}.
 */
class DnsAccount01ChallengeTest {

    private final Login login = TestUtils.login();

    /**
     * Test that {@link DnsAccount01Challenge} generates a correct authorization key.
     */
    @Test
    public void testDnsChallenge() {
        var challenge = new DnsAccount01Challenge(login, getJSON("dnsAccount01Challenge"));

        assertThat(challenge.getType()).isEqualTo(DnsAccount01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getDigest()).isEqualTo("MSB8ZUQOmbNfHors7PG580PBz4f9hDuOPDN_j1bNcXI");
        assertThat(challenge.getAuthorization()).isEqualTo("ODE4OWY4NTktYjhmYS00YmY1LTk5MDgtZTFjYTZmNjZlYTUx.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0");

        assertThat(challenge.getRRName("www.example.org"))
                .isEqualTo("_agozs7u2dml4wbyd._acme-challenge.www.example.org.");
        assertThat(challenge.getRRName(Identifier.dns("www.example.org")))
                .isEqualTo("_agozs7u2dml4wbyd._acme-challenge.www.example.org.");
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> challenge.getRRName(Identifier.ip("127.0.0.10")));

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

}