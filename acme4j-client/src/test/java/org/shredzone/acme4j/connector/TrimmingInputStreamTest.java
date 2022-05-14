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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link TrimmingInputStream}.
 */
public class TrimmingInputStreamTest {
    private final static String FULL_TEXT =
              "Gallia est omnis divisa in partes tres,\r\n\r\n\r\n"
            + "quarum unam incolunt Belgae, aliam Aquitani,\r\r\r\n\n"
            + "tertiam, qui ipsorum lingua Celtae, nostra Galli appellantur.";

    private final static String TRIMMED_TEXT =
              "Gallia est omnis divisa in partes tres,\n"
            + "quarum unam incolunt Belgae, aliam Aquitani,\n"
            + "tertiam, qui ipsorum lingua Celtae, nostra Galli appellantur.";

    @Test
    public void testEmpty() throws IOException {
        String out = trimByStream("");
        assertThat(out).isEqualTo("");
    }

    @Test
    public void testLineBreakOnly() throws IOException {
        String out1 = trimByStream("\n");
        assertThat(out1).isEqualTo("");

        String out2 = trimByStream("\r");
        assertThat(out2).isEqualTo("");

        String out3 = trimByStream("\r\n");
        assertThat(out2).isEqualTo("");
    }

    @Test
    public void testTrim() throws IOException {
        String out = trimByStream(FULL_TEXT);
        assertThat(out).isEqualTo(TRIMMED_TEXT);
    }

    @Test
    public void testTrimEndOnly() throws IOException {
        String out = trimByStream(FULL_TEXT + "\r\n\r\n");
        assertThat(out).isEqualTo(TRIMMED_TEXT + "\n");
    }

    @Test
    public void testTrimStartOnly() throws IOException {
        String out = trimByStream("\n\n" + FULL_TEXT);
        assertThat(out).isEqualTo(TRIMMED_TEXT);
    }

    @Test
    public void testTrimFull() throws IOException {
        String out = trimByStream("\n\n" + FULL_TEXT + "\r\n\r\n");
        assertThat(out).isEqualTo(TRIMMED_TEXT + "\n");
    }

    @Test
    public void testAvailable() throws IOException {
        try (TrimmingInputStream in = new TrimmingInputStream(
                new ByteArrayInputStream("Test".getBytes(StandardCharsets.US_ASCII)))) {
            assertThat(in.available()).isNotEqualTo(0);
        }
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
