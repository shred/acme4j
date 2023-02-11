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

import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.smime.challenge.EmailReply00Challenge;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;
import org.shredzone.acme4j.smime.wrapper.Mail;
import org.shredzone.acme4j.smime.wrapper.SignedMailBuilder;
import org.shredzone.acme4j.smime.wrapper.SimpleMail;

/**
 * A processor for incoming "Challenge" emails.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
 * @since 2.12
 */
public final class EmailProcessor {
    private static final Pattern SUBJECT_PATTERN = Pattern.compile("ACME:\\s+([0-9A-Za-z_\\s-]+=?)\\s*");

    private final InternetAddress sender;
    private final InternetAddress recipient;
    private final @Nullable String messageId;
    private final Collection<InternetAddress> replyTo;
    private final String token1;
    private final AtomicReference<EmailReply00Challenge> challengeRef = new AtomicReference<>();

    /**
     * Processes the given plain e-mail message.
     * <p>
     * Note that according to RFC-8823, the challenge message must be signed using either
     * DKIM or S/MIME. This method does not do any DKIM or S/MIME validation, and assumes
     * that this has already been done in a previous stage.
     *
     * @param message
     *         E-mail that was received from the CA. The inbound MTA has already taken
     *         care of DKIM and/or S/MIME validation.
     * @return EmailProcessor for this e-mail
     * @throws AcmeInvalidMessageException
     *         if a validation failed, and the message <em>must</em> be rejected.
     * @since 2.15
     */
    public static EmailProcessor plainMessage(Message message)
            throws AcmeInvalidMessageException {
        return builder().skipVerification().build(message);
    }

    /**
     * Processes the given signed e-mail message.
     * <p>
     * This method expects an S/MIME signed message. The signature must use a certificate
     * that can be validated using Java's cacert truststore. Strict validation rules are
     * applied.
     * <p>
     * Use the {@link #builder()} method if you need to configure the validation process.
     *
     * @param message
     *         S/MIME signed e-mail that was received from the CA.
     * @return EmailProcessor for this e-mail
     * @throws AcmeInvalidMessageException
     *         if a validation failed, and the message <em>must</em> be rejected.
     * @since 2.16
     */
    public static EmailProcessor signedMessage(Message message)
            throws AcmeInvalidMessageException {
        return builder().build(message);
    }

    /**
     * Creates a {@link Builder} for building an {@link EmailProcessor} with individual
     * configuration.
     *
     * @since 2.16
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Performs an S/MIME validation and processes the given e-mail message.
     * <p>
     * The owner of the given certificate must be the sender of that email.
     *
     * @param message
     *         E-mail that was received from the CA.
     * @param mailSession
     *         A {@link Session} that can be used for processing inner e-mails.
     * @param signCert
     *         The signing certificate of the sender.
     * @param strict
     *         If {@code true}, the S/MIME protected headers "From", "To", and "Subject"
     *         <em>must</em> match the headers of the received message. If {@code false},
     *         only the S/MIME protected headers are used, and the headers of the received
     *         message are ignored.
     * @return EmailProcessor for this e-mail
     * @throws AcmeInvalidMessageException
     *         if a validation failed, and the message <em>must</em> be rejected.
     * @since 2.15
     * @deprecated Use {@link #signedMessage(Message)} or {@link #builder()} instead.
     */
    @Deprecated
    public static EmailProcessor smimeMessage(Message message, Session mailSession,
                                              X509Certificate signCert, boolean strict)
            throws AcmeInvalidMessageException {
        Builder builder = builder()
                .mailSession(mailSession)
                .certificate(signCert);
        if (strict) {
            builder.strict();
        } else {
            builder.relaxed();
        }
        return builder.build(message);
    }

    /**
     * Creates a new {@link EmailProcessor} for the incoming "Challenge" message.
     * <p>
     * The incoming message is validated against the requirements of RFC-8823.
     *
     * @param message
     *         "Challenge" message as it was sent by the CA.
     * @throws AcmeInvalidMessageException
     *         if a validation failed, and the message <em>must</em> be rejected.
     */
    private EmailProcessor(Mail message) throws AcmeInvalidMessageException {
        if (!message.isAutoSubmitted()) {
            throw new AcmeInvalidMessageException("Message is not auto-generated");
        }

        String subject = message.getSubject();
        Matcher m = SUBJECT_PATTERN.matcher(subject);
        if (!m.matches()) {
            throw new AcmeProtocolException("Invalid subject: " + subject);
        }
        // white spaces within the token part must be ignored
        this.token1 = m.group(1).replaceAll("\\s+", "");

        this.sender = message.getFrom();
        this.recipient = message.getTo();
        this.messageId = message.getMessageId().orElse(null);
        this.replyTo = message.getReplyTo();
    }

    /**
     * The expected sender of the "challenge" email.
     * <p>
     * The sender is usually checked when the {@link EmailReply00Challenge} is passed into
     * the processor, but you can also manually check the sender here.
     *
     * @param expectedSender
     *         The expected sender of the "challenge" email.
     * @return itself
     * @throws AcmeProtocolException
     *         if the expected sender does not match
     */
    public EmailProcessor expectedFrom(InternetAddress expectedSender) {
        requireNonNull(expectedSender, "expectedSender");
        if (!sender.equals(expectedSender)) {
            throw new AcmeProtocolException("Message is not sent by the expected sender");
        }
        return this;
    }

    /**
     * The expected recipient of the "challenge" email.
     * <p>
     * This must be the email address of the entity that requested the S/MIME certificate.
     * The check is not performed by the processor, but <em>should</em> be performed by
     * the client.
     *
     * @param expectedRecipient
     *         The expected recipient of the "challenge" email.
     * @return itself
     * @throws AcmeProtocolException
     *         if the expected recipient does not match
     */
    public EmailProcessor expectedTo(InternetAddress expectedRecipient) {
        requireNonNull(expectedRecipient, "expectedRecipient");
        if (!recipient.equals(expectedRecipient)) {
            throw new AcmeProtocolException("Message is not addressed to expected recipient");
        }
        return this;
    }

    /**
     * The expected identifier.
     * <p>
     * This must be the email address of the entity that requested the S/MIME certificate.
     * The check is not performed by the processor, but <em>should</em> be performed by
     * the client.
     *
     * @param expectedIdentifier
     *         The expected identifier for the S/MIME certificate. Usually this is an
     *         {@link org.shredzone.acme4j.smime.EmailIdentifier} instance.
     * @return itself
     * @throws AcmeProtocolException
     *         if the expected identifier is not an email identifier, or does not match
     */
    public EmailProcessor expectedIdentifier(Identifier expectedIdentifier) {
        requireNonNull(expectedIdentifier, "expectedIdentifier");
        if (!"email".equals(expectedIdentifier.getType())) {
            throw new AcmeProtocolException("Wrong identifier type: " + expectedIdentifier.getType());
        }
        try {
            expectedTo(new InternetAddress(expectedIdentifier.getValue()));
        } catch (MessagingException ex) {
            throw new AcmeProtocolException("Invalid email address", ex);
        }
        return this;
    }

    /**
     * Returns the sender of the "challenge" email.
     */
    public InternetAddress getSender() {
        return sender;
    }

    /**
     * Returns the recipient of the "challenge" email.
     */
    public InternetAddress getRecipient() {
        return recipient;
    }

    /**
     * Returns all "reply-to" email addresses found in the "challenge" email.
     * <p>
     * Empty if there was no reply-to header, but never {@code null}.
     */
    public Collection<InternetAddress> getReplyTo() {
        return replyTo;
    }

    /**
     * Returns the message-id of the "challenge" email.
     * <p>
     * Empty if the challenge email has no message-id.
     */
    public Optional<String> getMessageId() {
        return Optional.ofNullable(messageId);
    }

    /**
     * Returns the "token 1" found in the subject of the "challenge" email.
     */
    public String getToken1() {
        return token1;
    }

    /**
     * Sets the corresponding {@link EmailReply00Challenge} that was received from the CA
     * for validation.
     *
     * @param challenge
     *         {@link EmailReply00Challenge} that corresponds to this email
     * @return itself
     * @throws AcmeProtocolException
     *         if the challenge does not match this "challenge" email.
     */
    public EmailProcessor withChallenge(EmailReply00Challenge challenge) {
        requireNonNull(challenge, "challenge");
        expectedFrom(challenge.getExpectedSender());
        if (challengeRef.get() != null) {
            throw new IllegalStateException("A challenge has already been set");
        }
        challengeRef.set(challenge);
        return this;
    }

    /**
     * Sets the corresponding {@link EmailReply00Challenge} that was received from the CA
     * for validation.
     * <p>
     * This is a convenience call in case that only the challenge location URL is
     * available.
     *
     * @param login
     *         A valid {@link Login}
     * @param challengeLocation
     *         The location URL of the corresponding challenge.
     * @return itself
     * @throws AcmeProtocolException
     *         if the challenge does not match this "challenge" email.
     */
    public EmailProcessor withChallenge(Login login, URL challengeLocation) {
        return withChallenge(login.bindChallenge(challengeLocation, EmailReply00Challenge.class));
    }

    /**
     * Returns the full token of this challenge.
     * <p>
     * The corresponding email-reply-00 challenge must be set before.
     */
    public String getToken() {
        checkChallengePresent();
        return challengeRef.get().getToken(getToken1());
    }

    /**
     * Returns the key-authorization of this challenge. This is the response to be used in
     * the response email.
     * <p>
     * The corresponding email-reply-00 challenge must be set before.
     */
    public String getAuthorization() {
        checkChallengePresent();
        return challengeRef.get().getAuthorization(getToken1());
    }

    /**
     * Returns a {@link ResponseGenerator} for generating a response email.
     * <p>
     * The corresponding email-reply-00 challenge must be set before.
     */
    public ResponseGenerator respond() {
        checkChallengePresent();
        return new ResponseGenerator(this);
    }

    /**
     * Checks if a challenge has been set. Throws an exception if not.
     */
    private void checkChallengePresent() {
        if (challengeRef.get() == null) {
            throw new IllegalStateException("No challenge has been set yet");
        }
    }

    /**
     * A builder for {@link EmailProcessor}.
     * <p>
     * Use {@link EmailProcessor#builder()} to generate an instance.
     *
     * @since 2.16
     */
    public static class Builder {
        private boolean unsigned = false;
        private final SignedMailBuilder builder = new SignedMailBuilder();

        private Builder() {
            // Private constructor
        }

        /**
         * Skips signature and header verification. Use only if the message has already
         * been verified in a previous stage (e.g. by the MTA) or for testing purposes.
         */
        public Builder skipVerification() {
            this.unsigned = true;
            return this;
        }

        /**
         * Uses the standard cacerts truststore for signature verification. This is the
         * default.
         */
        public Builder caCerts() {
            builder.withCaCertsTrustStore();
            return this;
        }

        /**
         * Uses the given truststore for signature verification.
         * <p>
         * This is for self-signed certificates. No revocation checks will take place.
         *
         * @param trustStore
         *         {@link KeyStore} of the truststore to be used.
         */
        public Builder trustStore(KeyStore trustStore) {
            try {
                builder.withTrustStore(trustStore);
            } catch (KeyStoreException | InvalidAlgorithmParameterException ex) {
                throw new IllegalArgumentException("Cannot use trustStore", ex);
            }
            return this;
        }

        /**
         * Uses the given certificate for signature verification.
         * <p>
         * This is for self-signed certificates. No revocation checks will take place.
         *
         * @param certificate
         *         {@link X509Certificate} of the CA
         */
        public Builder certificate(X509Certificate certificate) {
            builder.withSignCert(certificate);
            return this;
        }

        /**
         * Uses the given {@link PKIXParameters}.
         *
         * @param param
         *         {@link PKIXParameters} to be used for signature verification.
         */
        public Builder pkixParameters(PKIXParameters param) {
            builder.withPKIXParameters(param);
            return this;
        }

        /**
         * Uses the given mail {@link Session} for accessing the signed message body. A
         * simple default session is used otherwise, which is usually sufficient.
         *
         * @param session
         *         {@link Session} to be used for accessing the message body.
         */
        public Builder mailSession(Session session) {
            builder.withMailSession(session);
            return this;
        }

        /**
         * Performs strict checks. Secured headers must exactly match their unsecured
         * counterparts. This is the default.
         */
        public Builder strict() {
            builder.relaxed(false);
            return this;
        }

        /**
         * Performs relaxed checks. Secured headers might differ in whitespaces or case of
         * the field names. Use this if your MTA has mangled the envelope header.
         */
        public Builder relaxed() {
            builder.relaxed(true);
            return this;
        }

        /**
         * Builds an {@link EmailProcessor} for the given {@link Message} using the
         * current configuration.
         *
         * @param message
         *         {@link Message} to create an {@link EmailProcessor} for.
         * @return The generated {@link EmailProcessor}
         * @throws AcmeInvalidMessageException
         *         if the message fails to be verified. If this exception is thrown, the
         *         message MUST be rejected, and MUST NOT be used for certification.
         */
        public EmailProcessor build(Message message) throws AcmeInvalidMessageException {
            if (unsigned) {
                return new EmailProcessor(new SimpleMail(message));
            } else {
                return new EmailProcessor(builder.build(message));
            }
        }
    }

}
