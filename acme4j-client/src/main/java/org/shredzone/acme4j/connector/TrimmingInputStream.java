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

import java.io.IOException;
import java.io.InputStream;

/**
 * Normalizes line separators in an InputStream. Converts all line separators to '\n'.
 * Multiple line separators are compressed to a single line separator.
 */
public class TrimmingInputStream extends InputStream {

    private final InputStream in;
    private boolean wasLineSeparator = true;

    /**
     * Creates a new {@link TrimmingInputStream}.
     *
     * @param in
     *            {@link InputStream} to read from. Will be closed when this stream is
     *            closed.
     */
    public TrimmingInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public int read() throws IOException {
        int ch = in.read();

        if (wasLineSeparator) {
            while (isLineSeparator(ch)) {
                ch = in.read();
            }
        }

        wasLineSeparator = isLineSeparator(ch);

        if (ch == '\r') {
            ch = '\n';
        }

        return ch;
    }

    @Override
    public void close() throws IOException {
        in.close();
        super.close();
    }

    /**
     * Checks if the character is a line separator.
     */
    private static boolean isLineSeparator(int ch) {
        return ch == '\n' || ch == '\r';
    }

}
