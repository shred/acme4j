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

import static java.util.Objects.requireNonNull;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

import jakarta.mail.Address;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;

/**
 * Represents a simple, unsigned {@link Message}.
 * <p>
 * There is no signature validation at all. Use this class only for testing purposes,
 * or if a validation has already been performed in a separate step.
 *
 * @since 2.16
 */
public class SimpleMail implements Mail {
    private static final String HEADER_MESSAGE_ID = "Message-ID";
    private static final String HEADER_AUTO_SUBMITTED = "Auto-Submitted";

    private final Message message;

    public SimpleMail(Message message) {
        this.message = requireNonNull(message, "message");
    }

    @Override
    public InternetAddress getFrom() throws AcmeInvalidMessageException {
        try {
            Address[] from = message.getFrom();
            if (from == null) {
                throw new AcmeInvalidMessageException("Missing required 'From' header");
            }
            if (from.length != 1) {
                throw new AcmeInvalidMessageException("Message must have exactly one sender, but has " + from.length);
            }
            if (!(from[0] instanceof InternetAddress)) {
                throw new AcmeInvalidMessageException("Invalid sender message type: " + from[0].getClass().getName());
            }
            return (InternetAddress) from[0];
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read 'From' header", ex);
        }
    }

    @Override
    public InternetAddress getTo() throws AcmeInvalidMessageException {
        try {
            Address[] to = message.getRecipients(Message.RecipientType.TO);
            if (to == null) {
                throw new AcmeInvalidMessageException("Missing required 'To' header");
            }
            if (to.length != 1) {
                throw new AcmeInvalidMessageException("Message must have exactly one recipient, but has " + to.length);
            }
            if (!(to[0] instanceof InternetAddress)) {
                throw new AcmeInvalidMessageException("Invalid recipient message type: " + to[0].getClass().getName());
            }
            return (InternetAddress) to[0];
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read 'To' header", ex);
        }
    }

    @Override
    public String getSubject() throws AcmeInvalidMessageException {
        try {
            String subject = message.getSubject();
            if (subject == null) {
                throw new AcmeInvalidMessageException("Message must have a subject");
            }
            return subject;
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read 'Subject' header", ex);
        }
    }

    @Override
    public Collection<InternetAddress> getReplyTo() throws AcmeInvalidMessageException {
        try {
            Address[] rto = message.getReplyTo();
            if (rto == null) {
                return Collections.emptyList();
            }
            return Collections.unmodifiableList(Arrays.stream(rto)
                    .filter(InternetAddress.class::isInstance)
                    .map(InternetAddress.class::cast)
                    .collect(Collectors.toList()));
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read 'Reply-To' header", ex);
        }
    }

    @Override
    public Optional<String> getMessageId() throws AcmeInvalidMessageException {
        try {
            String[] mid = message.getHeader(HEADER_MESSAGE_ID);
            if (mid == null || mid.length == 0) {
                return Optional.empty();
            }
            if (mid.length > 1) {
                throw new AcmeInvalidMessageException("Expected one Message-ID, but found " + mid.length);
            }
            return Optional.of(mid[0]);
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read '" + HEADER_MESSAGE_ID + "' header", ex);
        }
    }

    @Override
    public boolean isAutoSubmitted() throws AcmeInvalidMessageException {
        try {
            String[] autoSubmitted = message.getHeader(HEADER_AUTO_SUBMITTED);
            if (autoSubmitted == null) {
                return false;
            }
            return Arrays.stream(autoSubmitted)
                    .map(String::trim)
                    .map(String::toLowerCase)
                    .anyMatch(h -> h.equals("auto-generated") || h.startsWith("auto-generated;"));
        } catch (MessagingException ex) {
            throw new AcmeInvalidMessageException("Could not read '" + HEADER_AUTO_SUBMITTED + "' header", ex);
        }
    }

}
