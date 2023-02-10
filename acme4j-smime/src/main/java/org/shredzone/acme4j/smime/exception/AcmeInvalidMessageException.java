/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2022 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.exception;

import static java.util.Collections.unmodifiableList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.LocalizedException;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * This exception is thrown when the challenge message is invalid.
 * <p>
 * If this exception is thrown, the challenge message does not match the actual challenge,
 * and <em>must</em> be rejected.
 * <p>
 * Reasons may be:
 * <ul>
 *     <li>Unexpected sender address</li>
 *     <li>Bad S/MIME signature</li>
 * </ul>
 *
 * @since 2.15
 */
public class AcmeInvalidMessageException extends AcmeException {
    private static final long serialVersionUID = 5607857024718309330L;

    private final List<ErrorBundle> errors;

    /**
     * Creates a new {@link AcmeInvalidMessageException}.
     *
     * @param msg
     *         Reason of the exception
     */
    public AcmeInvalidMessageException(String msg) {
        super(msg);
        this.errors = Collections.emptyList();
    }

    /**
     * Creates a new {@link AcmeInvalidMessageException}.
     *
     * @param msg
     *         Reason of the exception
     * @param errors
     *         List of {@link ErrorBundle} with further details
     * @since 2.16
     */
    public AcmeInvalidMessageException(String msg, List<ErrorBundle> errors) {
        super(msg);
        this.errors = unmodifiableList(errors);
    }

    /**
     * Creates a new {@link AcmeInvalidMessageException}.
     *
     * @param msg
     *         Reason of the exception
     * @param cause
     *         Cause
     */
    public AcmeInvalidMessageException(String msg, Throwable cause) {
        super(msg, cause);
        List<ErrorBundle> errors = new ArrayList<>(1);
        Optional.ofNullable(cause)
                .filter(LocalizedException.class::isInstance)
                .map(LocalizedException.class::cast)
                .map(LocalizedException::getErrorMessage)
                .ifPresent(errors::add);
        this.errors = unmodifiableList(errors);
    }

    /**
     * Returns a list with further error details, if available. The list may be empty, but
     * is never {@code null}.
     *
     * @since 2.16
     */
    public List<ErrorBundle> getErrors() {
        return errors;
    }

}
