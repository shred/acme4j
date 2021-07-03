/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.email;

import static java.util.Objects.requireNonNull;
import static javax.mail.Message.RecipientType.TO;
import static org.shredzone.acme4j.smime.email.ResponseBodyGenerator.RESPONSE_BODY_TYPE;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A helper for creating an email response to the "challenge" email.
 * <p>
 * According to RFC-8823, the response email must have a DKIM or S/MIME signature. This is
 * <em>not</em> done by the response generator, because it is usually performed by the
 * outbound MTA.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
 * @since 2.12
 */
public class ResponseGenerator {
    private static final int LINE_LENGTH = 72;
    private static final String CRLF = "\r\n";

    private final EmailProcessor processor;
    private ResponseBodyGenerator generator = this::defaultBodyGenerator;
    private @Nullable String header;
    private @Nullable String footer;

    /**
     * Creates a new {@link ResponseGenerator}.
     *
     * @param processor
     *         {@link EmailProcessor} of the challenge email.
     */
    public ResponseGenerator(EmailProcessor processor) {
        this.processor = requireNonNull(processor, "processor");
    }

    /**
     * Adds a custom header to the response mail body.
     * <p>
     * There is no need to set a header, since the response email is usually not read by
     * humans. If a header is set, it must contain ASCII encoded plain text.
     *
     * @param header
     *         Header text to be used, or {@code null} if no header is to be used.
     * @return itself
     */
    public ResponseGenerator withHeader(@Nullable String header) {
        if (header != null && !header.endsWith(CRLF)) {
            this.header = header.concat(CRLF);
        } else {
            this.header = header;
        }
        return this;
    }

    /**
     * Adds a custom footer to the response mail body.
     * <p>
     * There is no need to set a footer, since the response email is usually not read by
     * humans. If a footer is set, it must contain ASCII encoded plain text.
     *
     * @param footer
     *         Footer text to be used, or {@code null} if no footer is to be used.
     * @return itself
     */
    public ResponseGenerator withFooter(@Nullable String footer) {
        this.footer = footer;
        return this;
    }

    /**
     * Sets a {@link ResponseBodyGenerator} that is used for generating a response body.
     * <p>
     * Use this generator to individually style the email body, for example to use a
     * multipart body. However be aware that the response mail is evaluated by a machine,
     * and usually not read by humans, so the body should be designed as simple as
     * possible.
     * <p>
     * The default body generator will just concatenate the header, the armored key
     * authorization body, and the footer.
     *
     * @param generator
     *         {@link ResponseBodyGenerator} to be used, or {@code null} to use the
     *         default one.
     * @return itself
     */
    public ResponseGenerator withGenerator(@Nullable ResponseBodyGenerator generator) {
        this.generator = generator != null ? generator : this::defaultBodyGenerator;
        return this;
    }

    /**
     * Generates the response email.
     * <p>
     * Note that according to RFC-8823, this message must have a valid DKIM or S/MIME
     * signature. This is <em>not</em> done here, but usually performed by the outbound
     * MTA.
     *
     * @param session
     *         {@code javax.mail} {@link Session} to be used for this mail.
     * @return Generated {@link Message}.
     */
    public Message generateResponse(Session session) throws MessagingException {
        Message response = new MimeMessage(requireNonNull(session, "session"));

        response.setSubject("Re: ACME: " + processor.getToken1());
        response.setFrom(processor.getRecipient());

        if (!processor.getReplyTo().isEmpty()) {
            for (InternetAddress rto : processor.getReplyTo()) {
                response.addRecipient(TO, rto);
            }
        } else {
            response.addRecipients(TO, new Address[] {processor.getSender()});
        }

        if (processor.getMessageId().isPresent()) {
            response.setHeader("In-Reply-To", processor.getMessageId().get());
        }

        String wrappedAuth = processor.getAuthorization()
                .replaceAll("(.{" + LINE_LENGTH + "})", "$1" + CRLF);
        StringBuilder responseBody = new StringBuilder();
        responseBody.append("-----BEGIN ACME RESPONSE-----").append(CRLF);
        responseBody.append(wrappedAuth);
        if (!wrappedAuth.endsWith(CRLF)) {
            responseBody.append(CRLF);
        }
        responseBody.append("-----END ACME RESPONSE-----").append(CRLF);

        generator.setContent(response, responseBody.toString());
        return response;
    }

    /**
     * The default body generator. It just sets the response body, optionally framed by
     * the given header and footer.
     *
     * @param response
     *         response {@link Message} to fill.
     * @param responseBody
     *         Response body that must be added to the message.
     */
    private void defaultBodyGenerator(Message response, String responseBody)
            throws MessagingException {
        StringBuilder body = new StringBuilder();
        if (header != null) {
            body.append(header);
        }
        body.append(responseBody);
        if (footer != null) {
            body.append(footer);
        }
        response.setContent(body.toString(), RESPONSE_BODY_TYPE);
    }

}
