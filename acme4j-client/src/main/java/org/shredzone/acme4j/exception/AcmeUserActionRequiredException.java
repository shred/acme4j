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

import java.net.URI;
import java.net.URL;

/**
 * An exception that is thrown when the user is required to take action as indicated.
 */
public class AcmeUserActionRequiredException extends AcmeServerException {
    private static final long serialVersionUID = 7719055447283858352L;

    private final URI tosUri;
    private final URL instance;

    /**
     * Creates a new {@link AcmeUserActionRequiredException}.
     *
     * @param type
     *            System readable error type (here
     *            {@code "urn:ietf:params:acme:error:userActionRequired"})
     * @param detail
     *            Human readable error message
     * @param tosUri
     *            {@link URI} of the terms-of-service document to accept
     * @param instance
     *            {@link URL} to be visited by a human, showing instructions for how to
     *            agree to the terms and conditions.
     */
    public AcmeUserActionRequiredException(String type, String detail, URI tosUri, URL instance) {
        super(type, detail);
        this.tosUri = tosUri;
        this.instance = instance;
    }

    /**
     * Returns the {@link URI} of the terms-of-service document to accept, or {@code null}
     * if the server did not provide a link to such a document.
     */
    public URI getTermsOfServiceUri() {
        return tosUri;
    }

    /**
     * Returns the {@link URL} of a document indicating the action required by the user,
     * or {@code null} if the server did not provide such a link.
     */
    public URL getInstance() {
        return instance;
    }

}
