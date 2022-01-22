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

import jakarta.mail.Message;
import jakarta.mail.MessagingException;

/**
 * A generator for the response body to be set to the {@link Message}.
 * <p>
 * This generator can be used to design the body of the outgoing response email. However,
 * note that the response email is evaluated by a machine and usually not read by humans,
 * so the design should be kept simple, and <em>must</em> be conformous to RFC-8823.
 * <p>
 * The {@code responseBody} must be a part of the response email body, otherwise the
 * validation will fail.
 * <p>
 * A minimal implementation is:
 * <pre>
 * response.setContent(responseBody, RESPONSE_BODY_TYPE);
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
 * @since 2.12
 */
@FunctionalInterface
public interface ResponseBodyGenerator {

    /**
     * The content-type of the response body: {@value #RESPONSE_BODY_TYPE}
     */
    public static final String RESPONSE_BODY_TYPE = "text/plain";

    /**
     * Sets the content of the {@link Message}.
     *
     * @param response
     *         {@link Message} to set the body content.
     * @param responseBody
     *         The response body that <em>must</em> be part of the email response, and
     *         <em>must</em> use {@value #RESPONSE_BODY_TYPE} content type.
     */
    void setContent(Message response, String responseBody) throws MessagingException;

}
