/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2023 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.wrapper;

import java.util.Collection;
import java.util.Optional;

import jakarta.mail.internet.InternetAddress;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;

/**
 * Provide access to all required fields of an email. The underlying implementation
 * has to take care about parsing, validation, and verification of security features.
 *
 * @since 2.16
 */
public interface Mail {

    /**
     * Returns the sender address.
     *
     * @throws AcmeInvalidMessageException
     *         if there is not exactly one "From" header, or if the sender address is
     *         invalid.
     */
    InternetAddress getFrom() throws AcmeInvalidMessageException;

    /**
     * Returns the recipient address.
     *
     * @throws AcmeInvalidMessageException
     *         if there is not exactly one "To" header, or if the recipient address is
     *         invalid.
     */
    InternetAddress getTo() throws AcmeInvalidMessageException;

    /**
     * Returns the subject.
     *
     * @throws AcmeInvalidMessageException if there is no "Subject" header.
     */
    String getSubject() throws AcmeInvalidMessageException;

    /**
     * Returns a collection of the reply-to addresses. Reply-to addresses that are not
     * {@link InternetAddress} type are ignored.
     *
     * @return Collection of reply-to addresses. May be empty, but is never {@code null}.
     * @throws AcmeInvalidMessageException
     *         if the "Reply-To" header could not be parsed
     */
    Collection<InternetAddress> getReplyTo() throws AcmeInvalidMessageException;

    /**
     * Returns the message ID.
     *
     * @return Message ID, or empty if there is no message ID header.
     * @throws AcmeInvalidMessageException
     *         if the "Message-ID" header could not be parsed
     */
    Optional<String> getMessageId() throws AcmeInvalidMessageException;

    /**
     * Checks if the mail was flagged as auto-generated.
     *
     * @return {@code true} if there is an "Auto-Submitted" header containing the string
     * "auto-generated", {@code false} otherwise.
     * @throws AcmeInvalidMessageException
     *         if the "Auto-Submitted" header could not be parsed.
     */
    boolean isAutoSubmitted() throws AcmeInvalidMessageException;

}
