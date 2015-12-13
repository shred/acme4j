/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Unit tests for {@link HttpConnector}.
 *
 * @author Richard "Shred" Körber
 */
public class HttpConnectorTest {

    /**
     * Test if a HTTP connection can be opened.
     * <p>
     * This test requires a network connection. It should be excluded from automated
     * builds.
     */
    @Test
    @Category(HttpURLConnection.class)
    public void testOpenConnection() throws IOException, URISyntaxException {
        HttpConnector connector = new HttpConnector();
        HttpURLConnection conn = connector.openConnection(new URI("http://example.com"));
        assertThat(conn, not(nullValue()));
        conn.connect();
        assertThat(conn.getResponseCode(), is(HttpURLConnection.HTTP_OK));
    }

}
