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

    /**
     * Creates a new {@link AcmeInvalidMessageException}.
     *
     * @param msg
     *            Reason of the exception
     */
    public AcmeInvalidMessageException(String msg) {
        super(msg);
    }

    /**
     * Creates a new {@link AcmeInvalidMessageException}.
     *
     * @param msg
     *            Reason of the exception
     * @param cause
     *            Cause
     */
    public AcmeInvalidMessageException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
