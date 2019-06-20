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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collection;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.exception.AcmeUserActionRequiredException;

/**
 * This is a factory of all kind of mock errors. They can be thrown to simulate error
 * conditions.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public final class MockError {

    private MockError() {
        // Utility class without constructor
    }

    /**
     * Generates a standard HTTP error. It can be used to simulate non-ACME related errors
     * (e.g. inadvertent connection to a plain web server).
     *
     * @param responseCode
     *         HTTP error code
     * @param responseMessage
     *         HTTP error message
     * @return {@link AcmeException} containing the HTTP error.
     */
    public static AcmeException httpError(int responseCode, String responseMessage) {
        return new AcmeException("HTTP " + responseCode + ": " + responseMessage);
    }

    /**
     * Generates a standard 404 "Not Found" error.
     *
     * @return {@link AcmeException} containing the HTTP error.
     */
    public static AcmeException notFound() {
        return httpError(HttpURLConnection.HTTP_NOT_FOUND, "Not Found");
    }

    /**
     * Generates a standard 405 "Method Not Allowed" error.
     *
     * @return {@link AcmeException} containing the HTTP error.
     */
    public static AcmeException methodNotAllowed() {
        return httpError(HttpURLConnection.HTTP_BAD_METHOD, "Method Not Allowed");
    }

    /**
     * Generates a "Network is not reachable" exception. It can be used to simulate
     * generic network issues.
     *
     * @return {@link AcmeNetworkException} with a "Network is not reachable" {@link
     * IOException} as root cause.
     */
    public static AcmeNetworkException networkUnreachable() {
        IOException ioException = new IOException("Network is not reachable");
        return new AcmeNetworkException(ioException);
    }

    /**
     * Generates a general problem. It can be used to simulate any ACME related server
     * error.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @param error
     *         ACME error (e.g. {@code "unauthorized"}). The ACME error name space will be
     *         prepended automatically.
     * @param detail
     *         Human readable detail
     * @return {@link AcmeServerException} containing the error
     */
    public static AcmeServerException problem(URL requestUrl, String error, String detail) {
        return new AcmeServerException(new ProblemBuilder(requestUrl)
                .error(error)
                .detail(detail)
                .build()
        );
    }

    /**
     * Generates an error that the client is not authorized to access the given URL.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @return {@link AcmeUnauthorizedException} containing the error
     */
    public static AcmeUnauthorizedException unauthorized(URL requestUrl) {
        return new AcmeUnauthorizedException(new ProblemBuilder(requestUrl)
                .error("unauthorized")
                .detail("You are not authorized for this operation")
                .build()
        );
    }

    /**
     * Generates an error that the user account was not found on server side.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @return {@link AcmeServerException} containing the error
     */
    public static AcmeServerException accountDoesNotExist(URL requestUrl) {
        return problem(requestUrl, "accountDoesNotExist", "Account does not exist");
    }

    /**
     * Generates an error that the provided nonce is invalid. This can be used to simulate
     * nonce errors.
     * <p>
     * Note that acme4j usually tries to resolve this issue transparently to the client,
     * by resending the request with a new nonce multiple times. The mock server behaves
     * differently. It immediately passes this error to the client, without prior
     * reattempts.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @return {@link AcmeServerException} containing the error
     */
    public static AcmeServerException badNonce(URL requestUrl) {
        return problem(requestUrl, "badNonce", "Bad nonce was used");
    }

    /**
     * Generates an error that an user action is required. It can be used to simulate the
     * case that the user must accept new terms of service before she is able to
     * continue.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @param instance
     *         {@link URL} the user must be pointed to in order to resolve the situation
     * @param tos
     *         Optional {@link URI} of the new terms of service document
     * @return {@link AcmeUserActionRequiredException} containing the error
     */
    public static AcmeUserActionRequiredException userActionRequired(URL requestUrl,
                 URL instance, @Nullable URI tos) {
        Problem problem = new ProblemBuilder(requestUrl)
                .error("userActionRequired")
                .detail("Terms of service have changed")
                .instance(instance)
                .build();
        return new AcmeUserActionRequiredException(problem, tos);
    }

    /**
     * Generates an error that a rate limit has been reached.
     *
     * @param requestUrl
     *         {@link URL} the client tried to access
     * @param rateLimits
     *         Optional collection of {@link URL} explaining which rate limits have been
     *         reached.
     * @param retryAfter
     *         Optional instant after which the rate limit will be lifted.
     * @return {@link AcmeRateLimitedException} containing the error
     */
    public static AcmeRateLimitedException rateLimited(URL requestUrl,
               @Nullable Collection<URL> rateLimits, @Nullable Instant retryAfter) {
        Problem problem = new ProblemBuilder(requestUrl)
                .error("rateLimited")
                .detail("Rate limit is exceeded")
                .build();
        return new AcmeRateLimitedException(problem, retryAfter, rateLimits);
    }

}
