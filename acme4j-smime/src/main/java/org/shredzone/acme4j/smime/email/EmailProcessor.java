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
import static jakarta.mail.Message.RecipientType.TO;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.mail.Address;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.operator.OperatorCreationException;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.smime.challenge.EmailReply00Challenge;
import org.shredzone.acme4j.smime.exception.AcmeInvalidMessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A processor for incoming "Challenge" emails.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8823">RFC 8823</a>
 * @since 2.12
 */
public final class EmailProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(EmailProcessor.class);
    private static final Pattern SUBJECT_PATTERN = Pattern.compile("ACME:\\s+([0-9A-Za-z_\\s-]+=?)\\s*");
    private static final int RFC822NAME = 1;

    private final String token1;
    private final Optional<String> messageId;
    private final InternetAddress sender;
    private final InternetAddress recipient;
    private final Collection<InternetAddress> replyTo;
    private final AtomicReference<EmailReply00Challenge> challengeRef = new AtomicReference<>();

    /**
     * Processes the given e-mail message.
     * <p>
     * Note that according to RFC-8823, the challenge message must be signed using either
     * DKIM or S/MIME. This method does not do any DKIM or S/MIME validation, and assumes
     * that this has already been done by the inbound MTA.
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
        return new EmailProcessor(message, null, false, null);
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
     */
    public static EmailProcessor smimeMessage(Message message, Session mailSession,
                                              X509Certificate signCert, boolean strict)
            throws AcmeInvalidMessageException {
        try {
            if (!(message instanceof MimeMessage)) {
                throw new AcmeInvalidMessageException("Not a S/MIME message");
            }
            MimeMessage mimeMessage = (MimeMessage) message;

            if (!(mimeMessage.getContent() instanceof MimeMultipart)) {
                throw new AcmeProtocolException("S/MIME signed email must contain MimeMultipart");
            }
            MimeMultipart mp = (MimeMultipart) message.getContent();

            SMIMESigned signed = new SMIMESigned(mp);

            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signCert);
            boolean hasMatch = false;
            for (SignerInformation signer : signed.getSignerInfos().getSigners()) {
                hasMatch |= signer.verify(verifier);
                if (hasMatch) {
                    break;
                }
            }
            if (!hasMatch) {
                throw new AcmeInvalidMessageException("The S/MIME signature is invalid");
            }

            MimeMessage content = signed.getContentAsMimeMessage(mailSession);
            if (!"message/rfc822; forwarded=no".equalsIgnoreCase(content.getContentType())) {
                throw new AcmeInvalidMessageException("Message does not contain protected headers");
            }

            MimeMessage body = new MimeMessage(mailSession, content.getInputStream());

            List<Address> validFromAddresses = Optional.ofNullable(signCert.getSubjectAlternativeNames())
                    .orElseGet(Collections::emptyList)
                    .stream()
                    .filter(l -> ((Number) l.get(0)).intValue() == RFC822NAME)
                    .map(l -> l.get(1).toString())
                    .map(l -> {
                        try {
                            return new InternetAddress(l);
                        } catch (AddressException ex) {
                            // Ignore invalid email addresses
                            LOG.debug("Certificate contains invalid e-mail address {}", l, ex);
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (validFromAddresses.isEmpty()) {
                throw new AcmeInvalidMessageException("Signing certificate does not provide a rfc822Name subjectAltName");
            }

            return new EmailProcessor(message, body, strict, validFromAddresses);
        } catch (IOException | MessagingException | CMSException | OperatorCreationException |
                 CertificateParsingException ex) {
            throw new AcmeInvalidMessageException("Invalid S/MIME mail", ex);
        }
    }

    /**
     * Creates a new {@link EmailProcessor} for the incoming "Challenge" message.
     * <p>
     * The incoming message is validated against the requirements of RFC-8823.
     *
     * @param message
     *         "Challenge" message as it was sent by the CA.
     * @param signedMessage
     *         The signed part of the challenge message if present, or {@code null}. The
     *         signature is assumed to be valid, and must be validated in a previous
     *         step.
     * @param strict
     *         If {@code true}, the S/MIME protected headers "From", "To", and "Subject"
     *         <em>must</em> match the headers of the received message. If {@code false},
     *         only the S/MIME protected headers are used, and the headers of the received
     *         message are ignored.
     * @param validFromAddresses
     *         A {@link List} of {@link Address} that were found in the certificate's
     *         rfc822Name subjectAltName extension. The mail's From address <em>must</em>
     *         be found in this list, otherwise the signed message will be rejected.
     *         {@code null} to disable this validation step.
     * @throws AcmeInvalidMessageException
     *         if a validation failed, and the message <em>must</em> be rejected.
     */
    private EmailProcessor(Message message, @Nullable MimeMessage signedMessage,
                           boolean strict, @Nullable List<Address> validFromAddresses)
            throws AcmeInvalidMessageException {
        requireNonNull(message, "message");

        // Validate challenge and extract token 1
        try {
            if (!isAutoGenerated(getOptional(m -> m.getHeader("Auto-Submitted"), message, signedMessage))) {
                throw new AcmeInvalidMessageException("Message is not auto-generated");
            }

            Address[] from = getMandatory(Message::getFrom, message, signedMessage, "From");
            if (from == null) {
                throw new AcmeInvalidMessageException("Message has no 'From' header");
            }
            if (from.length != 1 || from[0] == null) {
                throw new AcmeInvalidMessageException("Message must have exactly one sender, but has " + from.length);
            }
            if (validFromAddresses != null && !validFromAddresses.contains(from[0])) {
                throw new AcmeInvalidMessageException("Sender '" + from[0] + "' was not found in signing certificate");
            }
            if (strict && signedMessage != null) {
                Address[] outerFrom = message.getFrom();
                if (outerFrom == null || outerFrom.length != 1 || !from[0].equals(outerFrom[0])) {
                    throw new AcmeInvalidMessageException("Protected 'From' header does not match envelope header");
                }
            }
            sender = new InternetAddress(from[0].toString());

            Address[] to = getMandatory(m -> m.getRecipients(TO), message, signedMessage, "To");
            if (to == null) {
                throw new AcmeInvalidMessageException("Message has no 'To' header");
            }
            if (to.length != 1 || to[0] == null) {
                throw new AcmeProtocolException("Message must have exactly one recipient, but has " + to.length);
            }
            if (strict && signedMessage != null) {
                Address[] outerTo = message.getRecipients(TO);
                if (outerTo == null || outerTo.length != 1 || !to[0].equals(outerTo[0])) {
                    throw new AcmeInvalidMessageException("Protected 'To' header does not match envelope header");
                }
            }
            recipient = new InternetAddress(to[0].toString());

            String subject = getMandatory(Message::getSubject, message, signedMessage, "Subject");
            if (subject == null) {
                throw new AcmeInvalidMessageException("Message has no 'Subject' header");
            }
            if (strict && signedMessage != null &&
                    (message.getSubject() == null || !message.getSubject().equals(signedMessage.getSubject()))) {
                throw new AcmeInvalidMessageException("Protected 'Subject' header does not match envelope header");
            }
            Matcher m = SUBJECT_PATTERN.matcher(subject);
            if (!m.matches()) {
                throw new AcmeProtocolException("Invalid subject: " + subject);
            }
            // white spaces within the token part must be ignored
            this.token1 = m.group(1).replaceAll("\\s+", "");

            Address[] rto = getOptional(Message::getReplyTo, message, signedMessage);
            if (rto != null) {
                replyTo = Collections.unmodifiableList(Arrays.stream(rto)
                        .filter(InternetAddress.class::isInstance)
                        .map(InternetAddress.class::cast)
                        .collect(Collectors.toList()));
            } else {
                replyTo = Collections.emptyList();
            }

            String[] mid = getOptional(n -> n.getHeader("Message-ID"), message, signedMessage);
            if (mid != null && mid.length > 0) {
                messageId = Optional.of(mid[0]);
            } else {
                messageId = Optional.empty();
            }
        } catch (MessagingException ex) {
            throw new AcmeProtocolException("Invalid challenge email", ex);
        }
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
        return messageId;
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
     * Get an optional property from the message.
     * <p>
     * Optional property means: If there is a signed message, try to fetch the property
     * from there. If the property is not present, fetch it from the unsigned message
     * instead. If it's also not there, return {@code null}.
     *
     * @param getter
     *         The getter method of {@link Message} to be invoked
     * @param message
     *         The outer (unsigned) {@link Message} that serves as fallback
     * @param signedMessage
     *         The signed (inner) {@link Message} where the property is looked up first
     * @param <T>
     *         The expected result type
     * @return The mail property, or {@code null} if not found
     */
    @CheckForNull
    private <T> T getOptional(MessageFunction<Message, T> getter, Message message, @Nullable Message signedMessage)
            throws MessagingException {
        if (signedMessage != null) {
            T result = getter.apply(signedMessage);
            if (result != null) {
                return result;
            }
        }
        return getter.apply(message);
    }

    /**
     * Get a mandatory property from the message.
     * <p>
     * Mandatory means: If there is a signed message, the property <em>must</em> be
     * present there. The unsigned message is only queried as fallback if there is no
     * signed message at all.
     *
     * @param getter
     *         The getter method of {@link Message} to be invoked
     * @param message
     *         The outer (unsigned) {@link Message} that serves as fallback if there is
     *         no signed message.
     * @param signedMessage
     *         The signed (inner) {@link Message} where the property is expected, or
     *         {@code null} if there is no signed message.
     * @param header
     *         Name of the expected header
     * @param <T>
     *         The expected result type
     * @return The mail property, or {@code null} if not found
     */
    @CheckForNull
    private <T> T getMandatory(MessageFunction<Message, T> getter, Message message, @Nullable Message signedMessage, String header)
            throws MessagingException, AcmeInvalidMessageException {
        if (signedMessage != null) {
            T value = getter.apply(signedMessage);
            if (value == null) {
                throw new AcmeInvalidMessageException("Protected header '" + header + "' expected, but missing.");
            }
            return value;
        }
        return getter.apply(message);
    }

    /**
     * Checks if this message is "auto-generated".
     *
     * @param autoSubmitted
     *         Auto-Submitted header content
     * @return {@code true} if the mail was auto-generated.
     */
    private boolean isAutoGenerated(@Nullable String[] autoSubmitted) throws MessagingException {
        if (autoSubmitted == null || autoSubmitted.length == 0) {
            return false;
        }
        return Arrays.stream(autoSubmitted)
                .map(String::trim)
                .anyMatch(h -> h.startsWith("auto-generated"));
    }

    /**
     * Checks if a challenge has been set. Throws an exception if not.
     */
    private void checkChallengePresent() {
        if (challengeRef.get() == null) {
            throw new IllegalStateException("No challenge has been set yet");
        }
    }

    @FunctionalInterface
    private interface MessageFunction<M extends Message, R> {
        @CheckForNull
        R apply(M message) throws MessagingException;
    }

}
