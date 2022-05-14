/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
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

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link TokenChallenge}.
 */
public class TokenChallengeTest {

    /**
     * Test that invalid tokens are detected.
     */
    @Test
    public void testInvalidToken() throws IOException {
        TestableConnectionProvider provider = new TestableConnectionProvider();
        Login login = provider.createLogin();

        JSONBuilder jb = new JSONBuilder();
        jb.put("url", "https://example.com/acme/1234");
        jb.put("type", "generic");
        jb.put("token", "<script>someMaliciousCode()</script>");

        TokenChallenge challenge = new TokenChallenge(login, jb.toJSON());
        assertThrows(AcmeProtocolException.class, challenge::getToken);
        provider.close();
    }

}
