/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2026 Richard "Shred" Körber
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
import static org.assertj.core.api.Assertions.*;
import static org.shredzone.acme4j.toolbox.TestUtils.ACCOUNT_URL;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;

import java.time.Instant;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link DnsPersist01Challenge}.
 */
class DnsPersist01ChallengeTest {

    private final Login login = TestUtils.login();

    /**
     * Test that {@link DnsPersist01Challenge} generates a correct TXT record.
     */
    @Test
    public void testDnsChallenge() {
        var challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        assertThat(challenge.getType()).isEqualTo(DnsPersist01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);
        assertThat(challenge.getIssuerDomainNames()).containsExactly("authority.example", "ca.example.net");

        assertThat(challenge.getRRName("www.example.org"))
                .isEqualTo("_validation-persist.www.example.org.");
        assertThat(challenge.getRRName(Identifier.dns("www.example.org")))
                .isEqualTo("_validation-persist.www.example.org.");
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> challenge.getRRName(Identifier.ip("127.0.0.10")));

        assertThat(challenge.getRData())
                .isEqualTo("\"authority.example;\" \" accounturi=" + ACCOUNT_URL + "\"");

        assertThat(challenge.getAccountUrl().toString())
                .isEqualTo(ACCOUNT_URL);

        var response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

    /**
     * Test that {@link DnsPersist01Challenge} generates a correct TXT record.
     */
    @Test
    public void testBuilder() {
        var challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));
        var until = Instant.ofEpochSecond(1767225600L);

        assertThat(challenge.buildRData().build())
                .isEqualTo("\"authority.example;\" \" accounturi=" + ACCOUNT_URL + "\"");

        assertThat(challenge.buildRData().wildcard().build())
                .isEqualTo("\"authority.example;\" \" accounturi=" + ACCOUNT_URL + ";\" \" policy=wildcard\"");

        assertThat(challenge.buildRData().issuerDomainName("ca.example.net").build())
                .isEqualTo("\"ca.example.net;\" \" accounturi=" + ACCOUNT_URL + "\"");

        assertThat(challenge.buildRData().persistUntil(until).build())
                .isEqualTo("\"authority.example;\" \" accounturi=" + ACCOUNT_URL + ";\" \" persistUntil=1767225600\"");

        assertThat(challenge.buildRData()
                .wildcard()
                .issuerDomainName("ca.example.net")
                .persistUntil(until)
                .build()
        ).isEqualTo("\"ca.example.net;\" \" accounturi=" + ACCOUNT_URL + ";\" \" policy=wildcard;\" \" persistUntil=1767225600\"");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> challenge.buildRData().issuerDomainName("ca.invalid").build())
                .withMessage("Domain ca.invalid is not in the list of issuer-domain-names");
    }

    /**
     * Test that {@link DnsPersist01Challenge} generates a correct TXT record, without
     * quotes.
     */
    @Test
    public void testBuilderNoQuotes() {
        var challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));
        var until = Instant.ofEpochSecond(1767225600L);

        assertThat(challenge.buildRData().noQuotes().build())
                .isEqualTo("authority.example; accounturi=" + ACCOUNT_URL);

        assertThat(challenge.buildRData()
                .wildcard()
                .issuerDomainName("ca.example.net")
                .persistUntil(until)
                .noQuotes()
                .build()
        ).isEqualTo("ca.example.net; accounturi=" + ACCOUNT_URL + "; policy=wildcard; persistUntil=1767225600");
    }

    @Test
    public void testConstraintChecks() {
        var json = getJSON("dnsPersist01Challenge").toMap();

        // Must fail if issuer-domain-names is missing
        var json1 = new TreeMap<>(json);
        json1.remove("issuer-domain-names");
        var challenge1 = new DnsPersist01Challenge(login, JSON.fromMap(json1));
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(challenge1::getIssuerDomainNames)
                .withMessage("issuer-domain-names missing or empty");

        // Must fail if issuer-domain-names is empty
        var json2 = new TreeMap<>(json);
        json2.put("issuer-domain-names", new String[0]);
        var challenge2 = new DnsPersist01Challenge(login, JSON.fromMap(json2));
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(challenge2::getIssuerDomainNames)
                .withMessage("issuer-domain-names missing or empty");

        // Must not fail if issuer-domain-names contains exactly 10 records
        var json3 = new TreeMap<>(json);
        json3.put("issuer-domain-names", createDomainList(10));
        var challenge3 = new DnsPersist01Challenge(login, JSON.fromMap(json3));
        assertThatNoException()
                .isThrownBy(challenge3::getIssuerDomainNames);

        // Must fail if issuer-domain-names contains more than 10 records
        var json4 = new TreeMap<>(json);
        json4.put("issuer-domain-names", createDomainList(11));
        var challenge4 = new DnsPersist01Challenge(login, JSON.fromMap(json4));
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(challenge4::getIssuerDomainNames)
                .withMessage("issuer-domain-names size limit exceeded: 11 > 10");

        // Must fail if issuer-domain-names contains a trailing dot
        var json5 = new TreeMap<>(json);
        json5.put("issuer-domain-names", new String[] {"foo.example.com."});
        var challenge5 = new DnsPersist01Challenge(login, JSON.fromMap(json5));
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(challenge5::getIssuerDomainNames)
                .withMessage("issuer-domain-names must not have trailing dots");
    }

    private String[] createDomainList(int length) {
        var result = new String[length];
        for (var ix = 0; ix < length; ix++) {
            result[ix] = "foo" + ix + ".example.com";
        }
        return result;
    }

}