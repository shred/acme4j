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
package org.shredzone.acme4j.smime;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.smime.challenge.EmailReply00Challenge;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Some common helper methods for S/MIME unit tests.
 */
public abstract class SMIMETests {
    public static final String TOKEN_PART1 = "LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=";
    public static final String TOKEN_PART2 = "DGyRejmCefe7v4NfDGDKfA";
    public static final String TOKEN = TOKEN_PART1 + TOKEN_PART2;
    public static final String KEY_AUTHORIZATION = "AjXW0h9_4YMP6Sv-9tKQNUrapI0us7ayBn0nCGOkUsk";
    public static final String RESPONSE_BODY = "-----BEGIN ACME RESPONSE-----\r\n"
            + KEY_AUTHORIZATION + "\r\n"
            + "-----END ACME RESPONSE-----\r\n";

    protected final Session mailSession = Session.getDefaultInstance(new Properties());

    /**
     * Safely generates an {@link InternetAddress} from the given email address.
     */
    protected InternetAddress email(String address) {
        try {
            return new InternetAddress(address);
        } catch (MessagingException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    /**
     * Creates a mock {@link Message}.
     *
     * @param name
     *         Name of the mock message to be read from the test resources.
     * @return Mock {@link Message} that was created
     */
    protected Message mockMessage(String name) {
        try (InputStream in = SMIMETests.class.getResourceAsStream("/email/" + name + ".eml")) {
            return new MimeMessage(mailSession, in);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (MessagingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Returns a mock account key pair to be used for signing.
     */
    protected KeyPair mockAccountKey() {
        try (Reader r = new InputStreamReader(
                        SMIMETests.class.getResourceAsStream("/key.pem"),
                        StandardCharsets.UTF_8)) {
            return KeyPairUtils.readKeyPair(r);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Returns a mock {@link Login} that can be used for signing.
     */
    protected Login mockLogin() {
        Login login = mock(Login.class);
        when(login.getKeyPair()).thenReturn(mockAccountKey());
        return login;
    }

    /**
     * Returns a mock {@link EmailReply00Challenge}.
     *
     * @param name
     *         Resource name of the mock challenge
     * @return Generated {@link EmailReply00Challenge}
     */
    protected EmailReply00Challenge mockChallenge(String name) {
        return new EmailReply00Challenge(mockLogin(), getJSON(name));
    }

    /**
     * Reads a JSON string from json test files and parses it.
     *
     * @param key
     *            JSON resource
     * @return Parsed JSON resource
     */
    protected JSON getJSON(String key) {
        try {
            return JSON.parse(SMIMETests.class.getResourceAsStream("/json/" + key + ".json"));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Reads a certificate from the given resource.
     *
     * @param name
     *         Resource name of the certificate
     * @return X509Certificate that was read
     */
    protected X509Certificate readCertificate(String name) throws IOException {
        try (InputStream in = SMIMETests.class.getResourceAsStream("/" + name + ".pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (CertificateException ex) {
            throw new IOException(ex);
        }
    }

}
