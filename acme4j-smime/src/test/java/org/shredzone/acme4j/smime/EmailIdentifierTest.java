/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests of {@link EmailIdentifier}.
 */
public class EmailIdentifierTest {

    @Test
    public void testConstants() {
        assertThat(EmailIdentifier.TYPE_EMAIL).isEqualTo("email");
    }

    @ParameterizedTest
    @MethodSource("provideTestEmails")
    public void testEmail(Object input, String expected) {
        var id = input instanceof InternetAddress internetAddress
                ? EmailIdentifier.email(internetAddress)
                : EmailIdentifier.email(input.toString());

        assertThat(id.getType()).isEqualTo(EmailIdentifier.TYPE_EMAIL);
        assertThat(id.getValue()).isEqualTo(expected);
        assertThat(id.getEmailAddress().getAddress()).isEqualTo(expected);
    }

    public static Stream<Arguments> provideTestEmails() throws AddressException {
        return Stream.of(
                Arguments.of("email@example.com", "email@example.com"),
                Arguments.of(new InternetAddress("email@example.com"), "email@example.com"),
                Arguments.of(new InternetAddress("Example Corp <info@example.com>"), "info@example.com")
        );
    }

}