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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.AcmeUtils.*;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

/**
 * Unit tests for {@link AcmeUtils}.
 */
public class AcmeUtilsTest {

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
     * Test that {@code null} check works properly.
     */
    @Test
    public void testAssertNotNull() {
        AcmeUtils.assertNotNull(new Object(), "foo");

        try {
            AcmeUtils.assertNotNull(null, "bar");
            fail("null was accepted");
        } catch (NullPointerException ex) {
            // expected
        }
    }

}
