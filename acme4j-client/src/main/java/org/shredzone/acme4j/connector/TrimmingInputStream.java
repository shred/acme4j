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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Normalizes line separators in an InputStream. Converts all line separators to '\n'.
 * Multiple line separators are compressed to a single line separator. Leading line
 * separators are removed. Trailing line separators are compressed to a single separator.
 */
public class TrimmingInputStream extends InputStream {
    private final BufferedInputStream in;
    private boolean startOfFile = true;

    /**
     * Creates a new {@link TrimmingInputStream}.
     *
     * @param in
     *            {@link InputStream} to read from. Will be closed when this stream is
     *            closed.
     */
    public TrimmingInputStream(InputStream in) {
        this.in = new BufferedInputStream(in, 1024);
    }

    @Override
    public int read() throws IOException {
        var ch = in.read();

        if (!isLineSeparator(ch)) {
            startOfFile = false;
            return ch;
        }

        in.mark(1);
        ch = in.read();
        while (isLineSeparator(ch)) {
            in.mark(1);
            ch = in.read();
        }

        if (startOfFile) {
            startOfFile = false;
            return ch;
        } else {
            in.reset();
            return '\n';
        }
    }

    @Override
    public int available() throws IOException {
        // Workaround for https://github.com/google/conscrypt/issues/1068. Conscrypt
        // requires the stream to have at least one non-blocking byte available for
        // reading, otherwise generateCertificates() will not read the stream, but
        // immediately returns an empty list. This workaround pre-fills the buffer
        // of the BufferedInputStream by reading 1 byte ahead.
        if (in.available() == 0) {
            in.mark(1);
            var read = in.read();
            in.reset();
            if (read < 0) {
                return 0;
            }
        }
        return in.available();
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
