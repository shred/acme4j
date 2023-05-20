/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.TreeMap;

import javax.crypto.SecretKey;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.keys.HmacKey;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.provider.AcmeProvider;

/**
 * Some utility methods for unit tests.
 */
public final class TestUtils {
    public static final String N = "pZsTKY41y_CwgJ0VX7BmmGs_7UprmXQMGPcnSbBeJAjZHA9SyyJKaWv4fNUdBIAX3Y2QoZixj50nQLyLv2ng3pvEoRL0sx9ZHgp5ndAjpIiVQ_8V01TTYCEDUc9ii7bjVkgFAb4ValZGFJZ54PcCnAHvXi5g0ELORzGcTuRqHVAUckMV2otr0g0u_5bWMm6EMAbBrGQCgUGjbZQHjava1Y-5tHXZkPBahJ2LvKRqMmJUlr0anKuJJtJUG03DJYAxABv8YAaXFBnGw6kKJRpUFAC55ry4sp4kGy0NrK2TVWmZW9kStniRv4RaJGI9aZGYwQy2kUykibBNmWEQUlIwIw";
    public static final String E = "AQAB";
    public static final String KTY = "RSA";
    public static final String THUMBPRINT = "HnWjTDnyqlCrm6tZ-6wX-TrEXgRdeNu9G71gqxSO6o0";

    public static final String D_N = "tP7p9wOe0NWocwLu7h233i1JqUPW1MeLeilyHY7oMKnXZFyf1l0saqLcrBtOj3EyaG6qVfpiLEWEIiuWclPYSR_QSt9lCi9xAoWbYq9-mqseehXPaejynlIMsP2UiCAenSHjJEer6Ug6nFelGVgav3mypwYFUdvc18wI00clKYhRAc4dZodilRzDTLy95V1S3RCxGf-lE0XYg7ieO_ovSMERtH_7NsjZnBiaE7mwm0YZzreCr8oSuHwhC63kgY27FnCgH0h63LICSPVVDJZPLcWAmSXv1k0qoVTsRzFutRN6RB_96wqTTBi8Qm98lyCpXcsxa3BH-4TCvLEaa2KkeQ";
    public static final String D_E = "AQAB";
    public static final String D_KTY = "RSA";
    public static final String D_THUMBPRINT = "0VPbh7-I6swlkBu0TrNKSQp6d69bukzeQA0ksuX3FFs";

    public static final String ACME_SERVER_URI = "https://example.com/acme";
    public static final String ACCOUNT_URL = "https://example.com/acme/account/1";

    public static final String DUMMY_NONCE = Base64.getUrlEncoder().withoutPadding().encodeToString("foo-nonce-foo".getBytes());

    public static final NetworkSettings DEFAULT_NETWORK_SETTINGS = new NetworkSettings();

    private TestUtils() {
        // utility class without constructor
    }

    /**
     * Reads a resource as byte array.
     *
     * @param name
     *            Resource name
     * @return Resource content as byte array.
     */
    public static byte[] getResourceAsByteArray(String name) throws IOException {
        var buffer = new byte[2048];
        try (var in = TestUtils.class.getResourceAsStream(name);
                var out = new ByteArrayOutputStream()) {
            int len;
            while ((len = in.read(buffer)) >= 0) {
                out.write(buffer, 0, len);
            }
            return out.toByteArray();
        }
    }

    /**
     * Reads a JSON string from json test files and parses it.
     *
     * @param key
     *            JSON resource
     * @return Parsed JSON resource
     */
    public static JSON getJSON(String key) {
        try {
            return JSON.parse(TestUtils.class.getResourceAsStream("/json/" + key + ".json"));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Creates a {@link Session} instance. It uses {@link #ACME_SERVER_URI} as server URI.
     */
    public static Session session() {
        return new Session(URI.create(ACME_SERVER_URI));
    }

    /**
     * Creates a {@link Login} instance. It uses {@link #ACME_SERVER_URI} as server URI,
     * {@link #ACCOUNT_URL} as account URL, and a random key pair.
     */
    public static Login login() {
        try {
            return session().login(new URL(ACCOUNT_URL), createKeyPair());
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Creates an {@link URL} from a String. Only throws a runtime exception if the URL is
     * malformed.
     *
     * @param url
     *            URL to use
     * @return {@link URL} object
     */
    public static URL url(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException(url, ex);
        }
    }

    /**
     * Creates a {@link Session} instance. It uses {@link #ACME_SERVER_URI} as server URI.
     *
     * @param provider
     *            {@link AcmeProvider} to be used in this session
     */
    public static Session session(final AcmeProvider provider) {
        return new Session(URI.create(ACME_SERVER_URI)) {
            @Override
            public AcmeProvider provider() {
                return provider;
            }

            @Override
            public Connection connect() {
                return provider.connect(getServerUri(), DEFAULT_NETWORK_SETTINGS);
            }
        };
    }

    /**
     * Creates a standard account {@link KeyPair} for testing. The key pair is read from a
     * test resource and is guaranteed not to change between test runs.
     * <p>
     * The constants {@link #N}, {@link #E}, {@link #KTY} and {@link #THUMBPRINT} are
     * related to the returned key pair and can be used for asserting results.
     *
     * @return {@link KeyPair} for testing
     */
    public static KeyPair createKeyPair() throws IOException {
        try {
            var keyFactory = KeyFactory.getInstance(KTY);

            var publicKeySpec = new X509EncodedKeySpec(getResourceAsByteArray("/public.key"));
            var publicKey = keyFactory.generatePublic(publicKeySpec);

            var privateKeySpec = new PKCS8EncodedKeySpec(getResourceAsByteArray("/private.key"));
            var privateKey = keyFactory.generatePrivate(privateKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Creates a standard domain key pair for testing. This keypair is read from a test
     * resource and is guaranteed not to change between test runs.
     * <p>
     * The constants {@link #D_N}, {@link #D_E}, {@link #D_KTY} and {@link #D_THUMBPRINT}
     * are related to the returned key pair and can be used for asserting results.
     *
     * @return {@link KeyPair} for testing
     */
    public static KeyPair createDomainKeyPair() throws IOException {
        try {
            var keyFactory = KeyFactory.getInstance(KTY);

            var publicKeySpec = new X509EncodedKeySpec(getResourceAsByteArray("/domain-public.key"));
            var publicKey = keyFactory.generatePublic(publicKeySpec);

            var privateKeySpec = new PKCS8EncodedKeySpec(getResourceAsByteArray("/domain-private.key"));
            var privateKey = keyFactory.generatePrivate(privateKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Creates a random ECC key pair with the given curve name.
     *
     * @param name
     *            Curve name
     * @return {@link KeyPair} for testing
     */
    public static KeyPair createECKeyPair(String name) throws IOException {
        try {
            var ecSpec = new ECGenParameterSpec(name);
            var keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(ecSpec, new SecureRandom());
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Creates a HMAC key using the given hash algorithm.
     *
     * @param algorithm
     *            Name of the hash algorithm to be used
     * @return {@link SecretKey} for testing
     */
    public static SecretKey createSecretKey(String algorithm) throws IOException {
        try {
            var md = MessageDigest.getInstance(algorithm);
            md.update("Turpentine".getBytes()); // A random password
            var macKey = md.digest();
            return new HmacKey(macKey);
        } catch (NoSuchAlgorithmException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Creates a standard certificate chain for testing. This certificate is read from a
     * test resource and is guaranteed not to change between test runs.
     *
     * @param resource
     *         Name of the resource
     * @return List of {@link X509Certificate} for testing
     */
    public static List<X509Certificate> createCertificate(String resource) throws IOException {
        try (var in = TestUtils.class.getResourceAsStream(resource)) {
            var cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificates(in).stream()
                       .map(c -> (X509Certificate) c)
                       .collect(toUnmodifiableList());
        } catch (CertificateException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Creates a {@link Problem} with the given type and details.
     *
     * @param type
     *            Problem type
     * @param detail
     *            Problem details
     * @param instance
     *            Instance, or {@code null}
     * @return Created {@link Problem} object
     */
    public static Problem createProblem(URI type, String detail, @Nullable URL instance) {
        var jb = new JSONBuilder();
        jb.put("type", type);
        jb.put("detail", detail);
        if (instance != null) {
            jb.put("instance", instance);
        }

        return new Problem(jb.toJSON(), url("https://example.com/acme/1"));
    }

    /**
     * Generates a new keypair for unit tests, and return its N, E, KTY and THUMBPRINT
     * parameters to be set in the {@link TestUtils} class.
     */
    public static void main(String... args) throws Exception {
        var keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        var keyPair = keyGen.generateKeyPair();

        try (var out = new FileOutputStream("public.key")) {
            out.write(keyPair.getPublic().getEncoded());
        }

        try (var out = new FileOutputStream("private.key")) {
            out.write(keyPair.getPrivate().getEncoded());
        }

        var jwk = JsonWebKey.Factory.newJwk(keyPair.getPublic());
        var params = new TreeMap<>(jwk.toParams(OutputControlLevel.PUBLIC_ONLY));
        var md = MessageDigest.getInstance("SHA-256");
        md.update(JsonUtil.toJson(params).getBytes(UTF_8));
        var thumbprint = md.digest();

        System.out.println("N = " + params.get("n"));
        System.out.println("E = " + params.get("e"));
        System.out.println("KTY = " + params.get("kty"));
        System.out.println("THUMBPRINT = " + Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint));
    }

}
