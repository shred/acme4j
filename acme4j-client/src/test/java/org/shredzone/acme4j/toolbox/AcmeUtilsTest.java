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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.toolbox.AcmeUtils.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.BeforeClass;
import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils.PemLabel;

/**
 * Unit tests for {@link AcmeUtils}.
 */
public class AcmeUtilsTest {

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that constructor is private.
     */
    @Test
    public void testPrivateConstructor() throws Exception {
        Constructor<AcmeUtils> constructor = AcmeUtils.class.getDeclaredConstructor();
        assertThat(Modifier.isPrivate(constructor.getModifiers()), is(true));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    /**
     * Test sha-256 hash and hex encode.
     */
    @Test
    public void testSha256HashHexEncode() {
        String hexEncode = hexEncode(sha256hash("foobar"));
        assertThat(hexEncode, is("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"));
    }

    /**
     * Test base64 URL encode.
     */
    @Test
    public void testBase64UrlEncode() {
        String base64UrlEncode = base64UrlEncode(sha256hash("foobar"));
        assertThat(base64UrlEncode, is("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI"));
    }

    /**
     * Test base64 URL decode.
     */
    @Test
    public void testBase64UrlDecode() {
        byte[] base64UrlDecode = base64UrlDecode("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI");
        assertThat(base64UrlDecode, is(sha256hash("foobar")));
    }

    /**
     * Test ACE conversion.
     */
    @Test
    public void testToAce() {
        // Test ASCII domains in different notations
        assertThat(toAce("example.com"), is("example.com"));
        assertThat(toAce("   example.com  "), is("example.com"));
        assertThat(toAce("ExAmPlE.CoM"), is("example.com"));
        assertThat(toAce("foo.example.com"), is("foo.example.com"));
        assertThat(toAce("bar.foo.example.com"), is("bar.foo.example.com"));

        // Test IDN domains
        assertThat(toAce("ExÄmþle.¢öM"), is("xn--exmle-hra7p.xn--m-7ba6w"));

        // Test alternate separators
        assertThat(toAce("example\u3002com"), is("example.com"));
        assertThat(toAce("example\uff0ecom"), is("example.com"));
        assertThat(toAce("example\uff61com"), is("example.com"));

        // Test ACE encoded domains, they must not change
        assertThat(toAce("xn--exmle-hra7p.xn--m-7ba6w"),
                                  is("xn--exmle-hra7p.xn--m-7ba6w"));

        // Test null
        assertThat(toAce(null), is(nullValue()));
    }

    /**
     * Test if RSA using SHA-256 keys are properly detected.
     */
    @Test
    public void testRsaKey() throws Exception {
        KeyPair rsaKeyPair = TestUtils.createKeyPair();
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(rsaKeyPair.getPublic());

        String type = keyAlgorithm(jwk);

        assertThat(type, is("RS256"));
    }

    /**
     * Test if ECDSA using NIST P-256 curve and SHA-256 keys are properly detected.
     */
    @Test
    public void testP256ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp256r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = keyAlgorithm(jwk);

        assertThat(type, is("ES256"));
    }

    /**
     * Test if ECDSA using NIST P-384 curve and SHA-384 keys are properly detected.
     */
    @Test
    public void testP384ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp384r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = keyAlgorithm(jwk);

        assertThat(type, is("ES384"));
    }

    /**
     * Test if ECDSA using NIST P-521 curve and SHA-512 keys are properly detected.
     */
    @Test
    public void testP521ECKey() throws Exception {
        KeyPair ecKeyPair = TestUtils.createECKeyPair("secp521r1");
        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ecKeyPair.getPublic());

        String type = keyAlgorithm(jwk);

        assertThat(type, is("ES512"));
    }

    /**
     * Test if MAC key algorithms are properly detected.
     */
    @Test
    public void testMacKey() throws Exception {
        assertThat(macKeyAlgorithm(TestUtils.createSecretKey("SHA-256")), is("HS256"));
        assertThat(macKeyAlgorithm(TestUtils.createSecretKey("SHA-384")), is("HS384"));
        assertThat(macKeyAlgorithm(TestUtils.createSecretKey("SHA-512")), is("HS512"));
    }

    /**
     * Test valid strings.
     */
    @Test
    public void testParser() {
        assertThat(parseTimestamp("2015-12-27T22:58:35.006769519Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.00676951Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.0067695Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.006769Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.00676Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.0067Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.006Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.01Z"), isDate(2015, 12, 27, 22, 58, 35, 10));
        assertThat(parseTimestamp("2015-12-27T22:58:35.2Z"), isDate(2015, 12, 27, 22, 58, 35, 200));
        assertThat(parseTimestamp("2015-12-27T22:58:35Z"), isDate(2015, 12, 27, 22, 58, 35));
        assertThat(parseTimestamp("2015-12-27t22:58:35z"), isDate(2015, 12, 27, 22, 58, 35));

        assertThat(parseTimestamp("2015-12-27T22:58:35.006769519+02:00"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.006+02:00"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35+02:00"), isDate(2015, 12, 27, 20, 58, 35));

        assertThat(parseTimestamp("2015-12-27T21:58:35.006769519-02:00"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T21:58:35.006-02:00"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T21:58:35-02:00"), isDate(2015, 12, 27, 23, 58, 35));

        assertThat(parseTimestamp("2015-12-27T22:58:35.006769519+0200"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35.006+0200"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T22:58:35+0200"), isDate(2015, 12, 27, 20, 58, 35));

        assertThat(parseTimestamp("2015-12-27T21:58:35.006769519-0200"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T21:58:35.006-0200"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parseTimestamp("2015-12-27T21:58:35-0200"), isDate(2015, 12, 27, 23, 58, 35));
    }

    /**
     * Test invalid strings.
     */
    @Test
    public void testInvalid() {
        try {
            parseTimestamp("");
            fail("accepted empty string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parseTimestamp("abc");
            fail("accepted nonsense string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parseTimestamp("2015-12-27");
            fail("accepted year only string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parseTimestamp("2015-12-27T");
            fail("accepted year only string");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test that error prefix is correctly removed.
     */
    @Test
    public void testStripErrorPrefix() {
        assertThat(stripErrorPrefix("urn:ietf:params:acme:error:unauthorized"), is("unauthorized"));
        assertThat(stripErrorPrefix("urn:somethingelse:error:message"), is(nullValue()));
        assertThat(stripErrorPrefix(null), is(nullValue()));
    }

    /**
     * Test that {@link AcmeUtils#writeToPem(byte[], PemLabel, Writer)} writes a correct PEM
     * file.
     */
    @Test
    public void testWriteToPem() throws IOException, CertificateEncodingException {
        List<X509Certificate> certChain = TestUtils.createCertificate();

        ByteArrayOutputStream pemFile = new ByteArrayOutputStream();
        try (Writer w = new OutputStreamWriter(pemFile)) {
            for (X509Certificate cert : certChain) {
                AcmeUtils.writeToPem(cert.getEncoded(), AcmeUtils.PemLabel.CERTIFICATE, w);
            }
        }

        ByteArrayOutputStream originalFile = new ByteArrayOutputStream();
        try (InputStream in = getClass().getResourceAsStream("/cert.pem")) {
            byte[] buffer = new byte[2048];
            int len;
            while ((len = in.read(buffer)) >= 0) {
                originalFile.write(buffer, 0, len);
            }
        }

        assertThat(pemFile.toByteArray(), is(originalFile.toByteArray()));
    }

    /**
     * Test {@link AcmeUtils#getContentType(String)}.
     */
    @Test
    public void testGetContentType() {
        assertThat(AcmeUtils.getContentType(null), is(nullValue()));
        assertThat(AcmeUtils.getContentType("application/json"),
                        is("application/json"));
        assertThat(AcmeUtils.getContentType("Application/Problem+JSON"),
                        is("application/problem+json"));
        assertThat(AcmeUtils.getContentType("application/json; charset=utf-8"),
                        is("application/json"));
        assertThat(AcmeUtils.getContentType("application/json; charset=utf-8 (Plain text)"),
                        is("application/json"));
        assertThat(AcmeUtils.getContentType("application/json; charset=\"utf-8\""),
                        is("application/json"));
        assertThat(AcmeUtils.getContentType("application/json; charset=\"UTF-8\"; foo=4"),
                        is("application/json"));
        assertThat(AcmeUtils.getContentType(" application/json ;foo=4"),
                        is("application/json"));

        try {
            AcmeUtils.getContentType("application/json; charset=\"iso-8859-1\"");
            fail("Accepted bad charset");
        } catch (AcmeProtocolException ex) {
            // expected
        }
    }

    /**
     * Test that {@link AcmeUtils#validateContact(java.net.URI)} refuses invalid
     * contacts.
     */
    @Test
    public void testValidateContact() {
        AcmeUtils.validateContact(URI.create("mailto:foo@example.com"));

        try {
            AcmeUtils.validateContact(URI.create("mailto:foo@example.com,bar@example.com"));
            fail("multiple recipients are accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            AcmeUtils.validateContact(URI.create("mailto:foo@example.com?to=bar@example.com"));
            fail("hfields are accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            AcmeUtils.validateContact(URI.create("mailto:?to=foo@example.com"));
            fail("hfields are accepted");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Matches the given time.
     */
    private InstantMatcher isDate(int year, int month, int dom, int hour, int minute, int second) {
        return isDate(year, month, dom, hour, minute, second, 0);
    }

    /**
     * Matches the given time and milliseconds.
     */
    private InstantMatcher isDate(int year, int month, int dom, int hour, int minute, int second, int ms) {
        Instant cmp = ZonedDateTime.of(
                    year, month, dom, hour, minute, second, ms * 1_000_000,
                    ZoneId.of("UTC")).toInstant();
        return new InstantMatcher(cmp);
    }

    /**
     * Date matcher that gives a readable output on mismatch.
     */
    private static class InstantMatcher extends BaseMatcher<Instant> {
        private final Instant cmp;
        private final DateTimeFormatter dtf = DateTimeFormatter.ISO_INSTANT;

        public InstantMatcher(Instant cmp) {
            this.cmp = cmp;
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof Instant)) {
                return false;
            }

            Instant date = (Instant) item;
            return date.equals(cmp);
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(dtf.format(cmp));
        }

        @Override
        public void describeMismatch(Object item, Description description) {
            if (!(item instanceof Instant)) {
                description.appendText("is not an Instant");
                return;
            }

            Instant date = (Instant) item;
            description.appendText("was ").appendValue(dtf.format(date));
        }
    }

}
