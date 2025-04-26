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

import java.io.Serial;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Problem;

/**
 * The user is required to take manual action as indicated.
 * <p>
 * Usually this exception is thrown when the terms of service have changed, and the CA
 * requires an agreement to the new terms before proceeding.
 */
public class AcmeUserActionRequiredException extends AcmeServerException {
    @Serial
    private static final long serialVersionUID = 7719055447283858352L;

    private final @Nullable URI tosUri;

    /**
     * Creates a new {@link AcmeUserActionRequiredException}.
     *
     * @param problem
     *         {@link Problem} that caused the exception
     * @param tosUri
     *         {@link URI} of the terms-of-service document to accept, may be
     *         {@code null}
     */
    public AcmeUserActionRequiredException(Problem problem, @Nullable URI tosUri) {
        super(problem);
        this.tosUri = tosUri;
    }

    /**
     * Returns the {@link URI} of the terms-of-service document to accept. Empty
     * if the server did not provide a link to such a document.
     */
    public Optional<URI> getTermsOfServiceUri() {
        return Optional.ofNullable(tosUri);
    }

    /**
     * Returns the {@link URL} of a document that gives instructions on the actions to be
     * taken by a human.
     */
    public URL getInstance() {
        var instance = getProblem().getInstance()
                .orElseThrow(() -> new AcmeProtocolException("Instance URL required, but missing."));

        try {
            return instance.toURL();
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException("Bad instance URL: " + instance, ex);
        }
    }

    @Override
    public String toString() {
        return getProblem().getInstance()
                .map(uri -> "Please visit " + uri + " - details: " + getProblem())
                .orElseGet(super::toString);
    }

}
