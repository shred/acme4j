/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.connector;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

/**
 * Unit tests for {@link TrimmingInputStream}.
 */
public class TrimmingInputStreamTest {

    @Test
    public void testEmpty() throws IOException {
        String out = trimByStream("");
        assertThat(out, is(""));
    }

    @Test
    public void testTrim() throws IOException {
        String out = trimByStream("\n\n"
            + "Gallia est omnis divisa in partes tres,\r\n\r\n\r\n"
            + "quarum unam incolunt Belgae, aliam Aquitani,\r\r\r\n\n"
            + "tertiam, qui ipsorum lingua Celtae, nostra Galli appellantur.");
        assertThat(out, is("Gallia est omnis divisa in partes tres,\n"
            + "quarum unam incolunt Belgae, aliam Aquitani,\n"
            + "tertiam, qui ipsorum lingua Celtae, nostra Galli appellantur."));
    }

    /**
     * Trims a string by running it through the {@link TrimmingInputStream}.
     */
    private String trimByStream(String str) throws IOException {
        StringBuilder out = new StringBuilder();

        try (TrimmingInputStream in = new TrimmingInputStream(
                        new ByteArrayInputStream(str.getBytes(StandardCharsets.US_ASCII)))) {
            int ch;
            while ((ch = in.read()) >= 0) {
                out.append((char) ch);
            }
        }

        return out.toString();
    }

}
