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
package org.shredzone.acme4j.toolbox;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.IDN;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.WillNotClose;
import javax.annotation.concurrent.Immutable;
import javax.crypto.SecretKey;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.shredzone.acme4j.exception.AcmeProtocolException;

/**
 * Contains utility methods that are frequently used for the ACME protocol.
 * <p>
 * This class is internal. You may use it in your own code, but be warned that methods may
 * change their signature or disappear without prior announcement.
 */
@ParametersAreNonnullByDefault
public final class AcmeUtils {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final String ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:";

    private static final Pattern DATE_PATTERN = Pattern.compile(
                    "^(\\d{4})-(\\d{2})-(\\d{2})T"
                  + "(\\d{2}):(\\d{2}):(\\d{2})"
                  + "(?:\\.(\\d{1,3})\\d*)?"
                  + "(Z|[+-]\\d{2}:?\\d{2})$", Pattern.CASE_INSENSITIVE);

    private static final Pattern TZ_PATTERN = Pattern.compile(
                "([+-])(\\d{2}):?(\\d{2})$");

    private static final Pattern CONTENT_TYPE_PATTERN = Pattern.compile(
                "([^;]+)(?:;.*?charset=(\"?)([a-z0-9_-]+)(\\2))?.*", Pattern.CASE_INSENSITIVE);

    private static final Pattern MAIL_PATTERN = Pattern.compile("\\?|@.*,");

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("[0-9A-Za-z_-]*");

    private static final Base64.Encoder PEM_ENCODER = Base64.getMimeEncoder(64,
                "\n".getBytes(StandardCharsets.US_ASCII));

    /**
     * Enumeration of PEM labels.
     */
    @ParametersAreNonnullByDefault
    @Immutable
    public enum PemLabel {
        CERTIFICATE("CERTIFICATE"),
        CERTIFICATE_REQUEST("CERTIFICATE REQUEST"),
        PRIVATE_KEY("PRIVATE KEY"),
        PUBLIC_KEY("PUBLIC KEY");

        private final String label;

        PemLabel(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }


    private AcmeUtils() {
        // Utility class without constructor
    }

    /**
     * Computes a SHA-256 hash of the given string.
     *
     * @param z
     *            String to hash
     * @return Hash
     */
    public static byte[] sha256hash(String z) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(z.getBytes("UTF-8"));
            return md.digest();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new AcmeProtocolException("Could not compute hash", ex);
        }
    }

    /**
     * Hex encodes the given byte array.
     *
     * @param data
     *            byte array to hex encode
     * @return Hex encoded string of the data (with lower case characters)
     */
    public static String hexEncode(byte[] data) {
        char[] result = new char[data.length * 2];
        for (int ix = 0; ix < data.length; ix++) {
            int val = data[ix] & 0xFF;
            result[ix * 2] = HEX[val >>> 4];
            result[ix * 2 + 1] = HEX[val & 0x0F];
        }
        return new String(result);
    }

    /**
     * Base64 encodes the given byte array, using URL style encoding.
     *
     * @param data
     *            byte array to base64 encode
     * @return base64 encoded string
     */
    public static String base64UrlEncode(byte[] data) {
        return Base64Url.encode(data);
    }

    /**
     * Base64 decodes to a byte array, using URL style encoding.
     *
     * @param base64
     *            base64 encoded string
     * @return decoded data
     */
    public static byte[] base64UrlDecode(String base64) {
        return Base64Url.decode(base64);
    }

    /**
     * Validates that the given {@link String} is a valid base64url encoded value.
     *
     * @param base64
     *            {@link String} to validate
     * @return {@code true}: String contains a valid base64url encoded value.
     *         {@code false} if the {@link String} was {@code null} or contained illegal
     *         characters.
     * @since 2.6
     */
    public static boolean isValidBase64Url(@Nullable String base64) {
        return base64 != null && BASE64URL_PATTERN.matcher(base64).matches();
    }

    /**
     * ASCII encodes a domain name.
     * <p>
     * The conversion is done as described in
     * <a href="http://www.ietf.org/rfc/rfc3490.txt">RFC 3490</a>. Additionally, all
     * leading and trailing white spaces are trimmed, and the result is lowercased.
     * <p>
     * It is safe to pass in ACE encoded domains, they will be returned unchanged.
     *
     * @param domain
     *            Domain name to encode
     * @return Encoded domain name, white space trimmed and lower cased.
     */
    public static String toAce(String domain) {
        Objects.requireNonNull(domain, "domain");
        return IDN.toASCII(domain.trim()).toLowerCase();
    }

    /**
     * Analyzes the key used in the {@link JsonWebKey}, and returns the key algorithm
     * identifier for {@link JsonWebSignature}.
     *
     * @param jwk
     *            {@link JsonWebKey} to analyze
     * @return algorithm identifier
     * @throws IllegalArgumentException
     *             there is no corresponding algorithm identifier for the key
     */
    public static String keyAlgorithm(JsonWebKey jwk) {
        if (jwk instanceof EllipticCurveJsonWebKey) {
            EllipticCurveJsonWebKey ecjwk = (EllipticCurveJsonWebKey) jwk;

            switch (ecjwk.getCurveName()) {
                case "P-256":
                    return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;

                case "P-384":
                    return AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;

                case "P-521":
                    return AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;

                default:
                    throw new IllegalArgumentException("Unknown EC name "
                        + ecjwk.getCurveName());
            }

        } else if (jwk instanceof RsaJsonWebKey) {
            return AlgorithmIdentifiers.RSA_USING_SHA256;

        } else {
            throw new IllegalArgumentException("Unknown algorithm " + jwk.getAlgorithm());
        }
    }

    /**
     * Analyzes the {@link SecretKey}, and returns the key algorithm
     * identifier for {@link JsonWebSignature}.
     *
     * @param macKey
     *            {@link SecretKey} to analyze
     * @return algorithm identifier
     * @throws IllegalArgumentException
     *             there is no corresponding algorithm identifier for the key
     */
    public static String macKeyAlgorithm(SecretKey macKey) {
        if (!"HMAC".equals(macKey.getAlgorithm())) {
            throw new IllegalArgumentException("Bad algorithm: " + macKey.getAlgorithm());
        }

        int size = macKey.getEncoded().length * 8;
        switch (size) {
            case 256:
                return AlgorithmIdentifiers.HMAC_SHA256;

            case 384:
                return AlgorithmIdentifiers.HMAC_SHA384;

            case 512:
                return AlgorithmIdentifiers.HMAC_SHA512;

            default:
                throw new IllegalArgumentException("Bad key size: " + size);
        }
    }

    /**
     * Parses a RFC 3339 formatted date.
     *
     * @param str
     *            Date string
     * @return {@link Instant} that was parsed
     * @throws IllegalArgumentException
     *             if the date string was not RFC 3339 formatted
     * @see <a href="https://www.ietf.org/rfc/rfc3339.txt">RFC 3339</a>
     */
    public static Instant parseTimestamp(String str) {
        Matcher m = DATE_PATTERN.matcher(str);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal date: " + str);
        }

        int year = Integer.parseInt(m.group(1));
        int month = Integer.parseInt(m.group(2));
        int dom = Integer.parseInt(m.group(3));
        int hour = Integer.parseInt(m.group(4));
        int minute = Integer.parseInt(m.group(5));
        int second = Integer.parseInt(m.group(6));

        StringBuilder msStr = new StringBuilder();
        if (m.group(7) != null) {
            msStr.append(m.group(7));
        }
        while (msStr.length() < 3) {
            msStr.append('0');
        }
        int ms = Integer.parseInt(msStr.toString());

        String tz = m.group(8);
        if ("Z".equalsIgnoreCase(tz)) {
            tz = "GMT";
        } else {
            tz = TZ_PATTERN.matcher(tz).replaceAll("GMT$1$2:$3");
        }

        return ZonedDateTime.of(
                year, month, dom, hour, minute, second, ms * 1_000_000,
                ZoneId.of(tz)).toInstant();
    }

    /**
     * Strips the acme error prefix from the error string.
     * <p>
     * For example, for "urn:ietf:params:acme:error:unauthorized", "unauthorized" is
     * returned.
     *
     * @param type
     *            Error type to strip the prefix from. {@code null} is safe.
     * @return Stripped error type, or {@code null} if the prefix was not found.
     */
    @CheckForNull
    public static String stripErrorPrefix(@Nullable String type) {
        if (type != null && type.startsWith(ACME_ERROR_PREFIX)) {
            return type.substring(ACME_ERROR_PREFIX.length());
        } else {
            return null;
        }
    }

    /**
     * Writes an encoded key or certificate to a file in PEM format.
     *
     * @param encoded
     *            Encoded data to write
     * @param label
     *            {@link PemLabel} to be used
     * @param out
     *            {@link Writer} to write to. It will not be closed after use!
     */
    public static void writeToPem(byte[] encoded, PemLabel label, @WillNotClose Writer out)
                throws IOException {
        out.append("-----BEGIN ").append(label.toString()).append("-----\n");
        out.append(new String(PEM_ENCODER.encode(encoded), StandardCharsets.US_ASCII));
        out.append("\n-----END ").append(label.toString()).append("-----\n");
    }

    /**
     * Extracts the content type of a Content-Type header.
     *
     * @param header
     *            Content-Type header
     * @return Content-Type, or {@code null} if the header was invalid or empty
     * @throws AcmeProtocolException
     *             if the Content-Type header contains a different charset than "utf-8".
     */
    @CheckForNull
    public static String getContentType(@Nullable String header) {
        if (header != null) {
            Matcher m = CONTENT_TYPE_PATTERN.matcher(header);
            if (m.matches()) {
                String charset = m.group(3);
                if (charset != null && !"utf-8".equalsIgnoreCase(charset)) {
                    throw new AcmeProtocolException("Unsupported charset " + charset);
                }
                return m.group(1).trim().toLowerCase();
            }
        }
        return null;
    }

    /**
     * Validates a contact {@link URI}.
     *
     * @param contact
     *            Contact {@link URI} to validate
     * @throws IllegalArgumentException
     *             if the contact {@link URI} is not suitable for account contacts.
     */
    public static void validateContact(URI contact) {
        if ("mailto".equalsIgnoreCase(contact.getScheme())) {
            String address = contact.toString().substring(7);
            if (MAIL_PATTERN.matcher(address).find()) {
                throw new IllegalArgumentException(
                        "multiple recipients or hfields are not allowed: " + contact);
            }
        }
    }

}
