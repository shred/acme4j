/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.connection;

import static java.util.Collections.singleton;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;

/**
 * Unit tests for {@link MockError}.
 */
public class MockErrorTest {

    @Test
    public void testHttpError() {
        AcmeException ex = MockError.httpError(HttpURLConnection.HTTP_CONFLICT, "Conflict");
        assertThat(ex.getMessage(), is("HTTP 409: Conflict"));
    }

    @Test
    public void testNotFound() {
        AcmeException ex = MockError.notFound();
        assertThat(ex.getMessage(), is("HTTP 404: Not Found"));
    }

    @Test
    public void testMethodNotAllowed() {
        AcmeException ex = MockError.methodNotAllowed();
        assertThat(ex.getMessage(), is("HTTP 405: Method Not Allowed"));
    }

    @Test
    public void testNetworkUnreachable() {
        AcmeNetworkException ex = MockError.networkUnreachable();
        assertThat(ex.getMessage(), is("Network error"));
        assertThat(ex.getCause(), is(instanceOf(IOException.class)));
        assertThat(ex.getCause().getMessage(), is("Network is not reachable"));
    }

    @Test
    public void testProblem() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/foo");

        AcmeServerException ex = MockError.problem(requestUrl, "malformed", "Malformed request");
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:malformed")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:malformed")));
        assertThat(ex.getProblem().getDetail(), is("Malformed request"));
    }

    @Test
    public void testUnauthorized() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/foo");

        AcmeUnauthorizedException ex = MockError.unauthorized(requestUrl);
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:unauthorized")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:unauthorized")));
        assertThat(ex.getProblem().getDetail(), is("You are not authorized for this operation"));
    }

    @Test
    public void testAccountDoesNotExist() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/foo");

        AcmeServerException ex = MockError.accountDoesNotExist(requestUrl);
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        assertThat(ex.getProblem().getDetail(), is("Account does not exist"));
    }

    @Test
    public void testBadNonce() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/foo");

        AcmeServerException ex = MockError.badNonce(requestUrl);
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:badNonce")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:badNonce")));
        assertThat(ex.getProblem().getDetail(), is("Bad nonce was used"));
    }

    @Test
    public void testUserActionRequired() throws MalformedURLException, URISyntaxException {
        URL requestUrl = new URL("https://acme.test/foo");
        URL instance = new URL("https://acme.test/acceptNewTOS.html");
        URI tos = URI.create("https://acme.test/tos.html");

        AcmeUserActionRequiredException ex = MockError.userActionRequired(requestUrl, instance, tos);
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:userActionRequired")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:userActionRequired")));
        assertThat(ex.getProblem().getDetail(), is("Terms of service have changed"));
        assertThat(ex.getInstance(), is(instance));
        assertThat(ex.getProblem().getInstance(), is(instance.toURI()));
        assertThat(ex.getTermsOfServiceUri(), is(tos));
    }

    @Test
    public void testRateLimited() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/foo");
        Collection<URL> documents = singleton(new URL("https://acme.test/limits.html"));
        Instant retryAfter = Instant.now().plus(12, ChronoUnit.HOURS);

        AcmeRateLimitedException ex = MockError.rateLimited(requestUrl, documents, retryAfter);
        assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:rateLimited")));
        assertThat(ex.getProblem().getType(), is(URI.create("urn:ietf:params:acme:error:rateLimited")));
        assertThat(ex.getProblem().getDetail(), is("Rate limit is exceeded"));
        assertThat(ex.getRetryAfter(), is(retryAfter));

        // These are mock URLs, and thus they are never equal for Java.
        // We have to convert them to Strings first. URL.equals() sucketh.
        assertThat(ex.getDocuments().stream().map(URL::toString).collect(toList()),
                contains("https://acme.test/limits.html"));
    }

}
