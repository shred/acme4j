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
package org.shredzone.acme4j.exception;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

import org.shredzone.acme4j.Problem;

/**
 * An exception that is thrown when the user is required to take action as indicated.
 */
@ParametersAreNonnullByDefault
@Immutable
public class AcmeUserActionRequiredException extends AcmeServerException {
    private static final long serialVersionUID = 7719055447283858352L;

    private final URI tosUri;

    /**
     * Creates a new {@link AcmeUserActionRequiredException}.
     *
     * @param problem
     *            {@link Problem} that caused the exception
     * @param tosUri
     *            {@link URI} of the terms-of-service document to accept
     */
    public AcmeUserActionRequiredException(Problem problem, @Nullable URI tosUri) {
        super(problem);
        this.tosUri = tosUri;
    }

    /**
     * Returns the {@link URI} of the terms-of-service document to accept, or {@code null}
     * if the server did not provide a link to such a document.
     */
    @CheckForNull
    public URI getTermsOfServiceUri() {
        return tosUri;
    }

    /**
     * Returns the {@link URL} of a document indicating the action required by the user,
     * or {@code null} if the server did not provide such a link.
     */
    @CheckForNull
    public URL getInstance() {
        URI instance = getProblem().getInstance();

        if (instance == null) {
            return null;
        }

        try {
            return instance.toURL();
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException("Bad instance URL: " + instance.toString(), ex);
        }
    }

}
