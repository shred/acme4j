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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.AcmeUtils.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.security.KeyPair;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.BeforeClass;
import org.junit.Test;

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
     * Test sha-256 hash.
     */
    @Test
    public void testSha256Hash() {
        byte[] hash = sha256hash("foobar");
        byte[] expected = DatatypeConverter.parseHexBinary("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");
        assertThat(hash, is(expected));
    }

    /**
     * Test hex encode.
     */
    @Test
    public void testHexEncode() {
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
        assertThat(stripErrorPrefix("urn:acme:error:deprecated"), is("deprecated"));
        assertThat(stripErrorPrefix("urn:somethingelse:error:message"), is(nullValue()));
        assertThat(stripErrorPrefix(null), is(nullValue()));
    }

    /**
     * Matches the given time.
     */
    private DateMatcher isDate(int year, int month, int dom, int hour, int minute, int second) {
        return isDate(year, month, dom, hour, minute, second, 0);
    }

    /**
     * Matches the given time and milliseconds.
     */
    private DateMatcher isDate(int year, int month, int dom, int hour, int minute, int second, int ms) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(year, month - 1, dom, hour, minute, second);
        cal.set(Calendar.MILLISECOND, ms);
        return new DateMatcher(cal);
    }

    /**
     * Date matcher that gives a readable output on mismatch.
     */
    private static class DateMatcher extends BaseMatcher<Date> {
        private final Calendar cal;
        private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH);

        public DateMatcher(Calendar cal) {
            this.cal = cal;
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof Date)) {
                return false;
            }

            Date date = (Date) item;
            return date.equals(cal.getTime());
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(sdf.format(cal.getTime()));
        }

        @Override
        public void describeMismatch(Object item, Description description) {
            if (!(item instanceof Date)) {
                description.appendText("is not a Date");
                return;
            }

            Date date = (Date) item;
            description.appendText("was ").appendValue(sdf.format(date));
        }
    }

}
