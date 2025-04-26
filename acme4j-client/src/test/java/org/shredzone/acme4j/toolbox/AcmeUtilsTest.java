/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.toolbox;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Unit tests for {@link AcmeUtils}.
 */
public class AcmeUtilsTest {

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that constructor is private.
     */
    @Test
    public void testPrivateConstructor() throws Exception {
        var constructor = AcmeUtils.class.getDeclaredConstructor();
        assertThat(Modifier.isPrivate(constructor.getModifiers())).isTrue();
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    /**
     * Test sha-256 hash and hex encode.
     */
    @Test
    public void testSha256HashHexEncode() {
        var hexEncode = hexEncode(sha256hash("foobar"));
        assertThat(hexEncode).isEqualTo("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");
    }

    /**
     * Test base64 URL encode.
     */
    @Test
    public void testBase64UrlEncode() {
        var base64UrlEncode = base64UrlEncode(sha256hash("foobar"));
        assertThat(base64UrlEncode).isEqualTo("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI");
    }

    /**
     * Test base64 URL decode.
     */
    @Test
    public void testBase64UrlDecode() {
        var base64UrlDecode = base64UrlDecode("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI");
        assertThat(base64UrlDecode).isEqualTo(sha256hash("foobar"));
    }

    /**
     * Test base32 encode.
     */
    @ParameterizedTest
    @CsvSource({    // Test vectors according to RFC 4648 section 10
            "'',''",
            "f,MY======",
            "fo,MZXQ====",
            "foo,MZXW6===",
            "foob,MZXW6YQ=",
            "fooba,MZXW6YTB",
            "foobar,MZXW6YTBOI======",
    })
    public void testBase32Encode(String unencoded, String encoded) {
        assertThat(base32Encode(unencoded.getBytes(UTF_8))).isEqualTo(encoded);
    }

    /**
     * Test base64 URL validation for valid values
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "Zg",
            "Zm9v",
    })
    public void testBase64UrlValid(String url) {
        assertThat(isValidBase64Url(url)).isTrue();
    }

    /**
     * Test base64 URL validation for invalid values
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "         ",
            "Zg=",
            "Zg==",
            "   Zm9v   ",
            "<some>.illegal#Text",
    })
    @NullSource
    public void testBase64UrlInvalid(String url) {
        assertThat(isValidBase64Url(url)).isFalse();
    }

    /**
     * Test ACE conversion.
     */
    @Test
    public void testToAce() {
        // Test ASCII domains in different notations
        assertThat(toAce("example.com")).isEqualTo("example.com");
        assertThat(toAce("   example.com  ")).isEqualTo("example.com");
        assertThat(toAce("ExAmPlE.CoM")).isEqualTo("example.com");
        assertThat(toAce("foo.example.com")).isEqualTo("foo.example.com");
        assertThat(toAce("bar.foo.example.com")).isEqualTo("bar.foo.example.com");

        // Test IDN domains
        assertThat(toAce("ExÄmþle.¢öM")).isEqualTo("xn--exmle-hra7p.xn--m-7ba6w");

        // Test alternate separators
        assertThat(toAce("example\u3002com")).isEqualTo("example.com");
        assertThat(toAce("example\uff0ecom")).isEqualTo("example.com");
        assertThat(toAce("example\uff61com")).isEqualTo("example.com");

        // Test ACE encoded domains, they must not change
        assertThat(toAce("xn--exmle-hra7p.xn--m-7ba6w"))
                .isEqualTo("xn--exmle-hra7p.xn--m-7ba6w");
    }

    /**
     * Test valid strings.
     */
    @ParameterizedTest
    @MethodSource("provideTimestamps")
    public void testParser(String input, String expected) {
        Arguments.of(input, expected, within(1, ChronoUnit.MILLIS));
    }

    private static Stream<Arguments> provideTimestamps() {
        return Stream.of(
            Arguments.of("2015-12-27T22:58:35.006769519Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.00676951Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.0067695Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.006769Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.00676Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.0067Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.006Z", "2015-12-27T22:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.01Z", "2015-12-27T22:58:35.010Z"),
            Arguments.of("2015-12-27T22:58:35.2Z", "2015-12-27T22:58:35.200Z"),
            Arguments.of("2015-12-27T22:58:35Z", "2015-12-27T22:58:35.000Z"),
            Arguments.of("2015-12-27t22:58:35z", "2015-12-27T22:58:35.000Z"),

            Arguments.of("2015-12-27T22:58:35.006769519+02:00", "2015-12-27T20:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.006+02:00", "2015-12-27T20:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35+02:00", "2015-12-27T20:58:35.000Z"),

            Arguments.of("2015-12-27T21:58:35.006769519-02:00", "2015-12-27T23:58:35.006Z"),
            Arguments.of("2015-12-27T21:58:35.006-02:00", "2015-12-27T23:58:35.006Z"),
            Arguments.of("2015-12-27T21:58:35-02:00", "2015-12-27T23:58:35.000Z"),

            Arguments.of("2015-12-27T22:58:35.006769519+0200", "2015-12-27T20:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35.006+0200", "2015-12-27T20:58:35.006Z"),
            Arguments.of("2015-12-27T22:58:35+0200", "2015-12-27T20:58:35.000Z"),

            Arguments.of("2015-12-27T21:58:35.006769519-0200", "2015-12-27T23:58:35.006Z"),
            Arguments.of("2015-12-27T21:58:35.006-0200", "2015-12-27T23:58:35.006Z"),
            Arguments.of("2015-12-27T21:58:35-0200", "2015-12-27T23:58:35.000Z")
        );
    }

    /**
     * Test invalid strings.
     */
    @Test
    public void testInvalid() {
        assertThrows(IllegalArgumentException.class,
                () -> parseTimestamp(""),
                "accepted empty string");
        assertThrows(IllegalArgumentException.class,
                () -> parseTimestamp("abc"),
                "accepted nonsense string");
        assertThrows(IllegalArgumentException.class,
                () -> parseTimestamp("2015-12-27"),
                "accepted date only string");
        assertThrows(IllegalArgumentException.class,
                () -> parseTimestamp("2015-12-27T"),
                "accepted string without time");
    }

    /**
     * Test that locales are correctly converted to language headers.
     */
    @Test
    public void testLocaleToLanguageHeader() {
        assertThat(localeToLanguageHeader(Locale.ENGLISH))
                .isEqualTo("en,*;q=0.1");
        assertThat(localeToLanguageHeader(new Locale("en", "US")))
                .isEqualTo("en-US,en;q=0.8,*;q=0.1");
        assertThat(localeToLanguageHeader(Locale.GERMAN))
                .isEqualTo("de,*;q=0.1");
        assertThat(localeToLanguageHeader(Locale.GERMANY))
                .isEqualTo("de-DE,de;q=0.8,*;q=0.1");
        assertThat(localeToLanguageHeader(new Locale("")))
                .isEqualTo("*");
        assertThat(localeToLanguageHeader(null))
                .isEqualTo("*");
    }

    /**
     * Test that error prefix is correctly removed.
     */
    @Test
    public void testStripErrorPrefix() {
        assertThat(stripErrorPrefix("urn:ietf:params:acme:error:unauthorized")).isEqualTo("unauthorized");
        assertThat(stripErrorPrefix("urn:somethingelse:error:message")).isNull();
        assertThat(stripErrorPrefix(null)).isNull();
    }

    /**
     * Test that {@link AcmeUtils#writeToPem(byte[], PemLabel, Writer)} writes a correct PEM
     * file.
     */
    @Test
    public void testWriteToPem() throws IOException, CertificateEncodingException {
        var certChain = TestUtils.createCertificate("/cert.pem");

        var pemFile = new ByteArrayOutputStream();
        try (var w = new OutputStreamWriter(pemFile)) {
            for (var cert : certChain) {
                AcmeUtils.writeToPem(cert.getEncoded(), AcmeUtils.PemLabel.CERTIFICATE, w);
            }
        }

        var originalFile = new ByteArrayOutputStream();
        try (var in = getClass().getResourceAsStream("/cert.pem")) {
            var buffer = new byte[2048];
            int len;
            while ((len = in.read(buffer)) >= 0) {
                originalFile.write(buffer, 0, len);
            }
        }

        assertThat(pemFile.toByteArray()).isEqualTo(originalFile.toByteArray());
    }

    /**
     * Test {@link AcmeUtils#getContentType(String)} for JSON types.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "application/json",
            "application/json; charset=utf-8",
            "application/json; charset=utf-8 (Plain text)",
            "application/json; charset=\"utf-8\"",
            "application/json; charset=\"UTF-8\"; foo=4",
            " application/json ;foo=4",
    })
    public void testGetContentTypeForJson(String contentType) {
        assertThat(AcmeUtils.getContentType(contentType)).isEqualTo("application/json");
    }

    /**
     * Test {@link AcmeUtils#getContentType(String)} with other types.
     */
    @Test
    public void testGetContentType() {
        assertThat(AcmeUtils.getContentType(null)).isNull();
        assertThat(AcmeUtils.getContentType("Application/Problem+JSON"))
                .isEqualTo("application/problem+json");
        assertThrows(AcmeProtocolException.class,
                () -> AcmeUtils.getContentType("application/json; charset=\"iso-8859-1\""));
    }

    /**
     * Test that {@link AcmeUtils#validateContact(java.net.URI)} refuses invalid
     * contacts.
     */
    @Test
    public void testValidateContact() {
        AcmeUtils.validateContact(URI.create("mailto:foo@example.com"));

        assertThrows(IllegalArgumentException.class,
                () -> AcmeUtils.validateContact(URI.create("mailto:foo@example.com,bar@example.com")),
                "multiple recipients are accepted");
        assertThrows(IllegalArgumentException.class,
                () -> AcmeUtils.validateContact(URI.create("mailto:foo@example.com?to=bar@example.com")),
                "hfields are accepted");
        assertThrows(IllegalArgumentException.class,
                () -> AcmeUtils.validateContact(URI.create("mailto:?to=foo@example.com")),
                "only hfields are accepted");
    }

}
