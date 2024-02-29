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
 * Unit tests for {@link Dns01Challenge}.
 */
public class Dns01ChallengeTest {

    private final Login login = TestUtils.login();

    /**
     * Test that {@link Dns01Challenge} generates a correct authorization key.
     */
    @Test
    public void testDnsChallenge() {
        var challenge = new Dns01Challenge(login, getJSON("dnsChallenge"));

        assertThat(challenge.getType()).isEqualTo(Dns01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getDigest()).isEqualTo("rzMmotrIgsithyBYc0vgiLUEEKYx0WetQRgEF2JIozA");
        assertThat(challenge.getAuthorization()).isEqualTo("pNvmJivs0WCko2suV7fhe-59oFqyYx_yB7tx6kIMAyE.HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0");

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

    @Test
    public void testToRRName() {
        assertThat(Dns01Challenge.toRRName("www.example.org"))
                .isEqualTo("_acme-challenge.www.example.org.");
        assertThat(Dns01Challenge.toRRName(Identifier.dns("www.example.org")))
                .isEqualTo("_acme-challenge.www.example.org.");
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> Dns01Challenge.toRRName(Identifier.ip("127.0.0.10")));
        assertThat(Dns01Challenge.RECORD_NAME_PREFIX)
                .isEqualTo("_acme-challenge");
    }

}
