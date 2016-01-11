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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Map;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.shredzone.acme4j.Account;

/**
 * Unit test for {@link ValidationBuilder}.
 *
 * @author Richard "Shred" Körber
 */
public class ValidationBuilderTest {

    /**
     * Test if a correct JWS validation object is generated.
     */
    @Test
    public void testValidationBuilder() throws IOException, JoseException {
        Account account = new Account(TestUtils.createKeyPair());
        KeyPair domainKeyPair = TestUtils.createDomainKeyPair();

        assertThat(account.getKeyPair(), not(domainKeyPair));

        ValidationBuilder vb = new ValidationBuilder();
        vb.domain("abc.de").domain("ef.gh");
        vb.domains("ijk.lm", "no.pq", "rst.uv");
        vb.domains(Arrays.asList("w.x", "y.z"));
        String json = vb.sign(account, domainKeyPair);

        Map<String, Object> data = JsonUtil.parseJson(json);

        String header = (String) data.get("header");
        String payload = Base64Url.decodeToUtf8String((String) data.get("payload"));
        String signature = (String) data.get("signature");

        StringBuilder expectedHeader = new StringBuilder();
        expectedHeader.append('{');
        expectedHeader.append("\"alg\":\"RS256\",");
        expectedHeader.append("\"jwk\":{");
        expectedHeader.append("\"kty\":\"").append(TestUtils.D_KTY).append("\",");
        expectedHeader.append("\"e\":\"").append(TestUtils.D_E).append("\",");
        expectedHeader.append("\"n\":\"").append(TestUtils.D_N).append("\"");
        expectedHeader.append("}}");

        StringBuilder expectedPayload = new StringBuilder();
        expectedPayload.append('{');
        expectedPayload.append("\"type\":\"proof-of-possession-01\",");
        expectedPayload.append("\"identifiers\":[");
        for (String d : Arrays.asList("abc.de", "ef.gh", "ijk.lm", "no.pq", "rst.uv", "w.x", "y.z")) {
            expectedPayload.append("{\"type\":\"dns\",\"value\":\"").append(d).append("\"}");
            if (!"y.z".equals(d)) {
                expectedPayload.append(',');
            }
        }
        expectedPayload.append("],\"accountKey\":{");
        expectedPayload.append("\"kty\":\"").append(TestUtils.KTY).append("\",");
        expectedPayload.append("\"e\":\"").append(TestUtils.E).append("\",");
        expectedPayload.append("\"n\":\"").append(TestUtils.N).append("\"");
        expectedPayload.append("}}");

        assertThat(header, sameJSONAs(expectedHeader.toString()).allowingExtraUnexpectedFields());
        assertThat(payload, sameJSONAs(expectedPayload.toString()));
        assertThat(signature, not(isEmptyOrNullString()));
    }

}
