/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.it;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Map;

import org.shredzone.acme4j.it.server.TlsAlpnServer;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;

/**
 * Request handler for all {@code tls-alpn-01} related requests.
 */
public final class TlsAlpnHandler {

    public static final String ADD = "/tlsalpn/add/:alias";
    public static final String REMOVE = "/tlsalpn/remove/:alias";

    private TlsAlpnHandler() {
        // this class cannot be instanciated.
    }

    /**
     * Adds an TLS-ALPN certificate.
     */
    public static class Add extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String alias = urlParams.get("alias");
            String privateKeyEncoded = session.getParameters().get("privateKey").get(0);
            String certEncoded = session.getParameters().get("cert").get(0);

            Decoder base64 = Base64.getDecoder();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(
                    base64.decode(privateKeyEncoded)));

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(base64.decode(certEncoded)));

            TlsAlpnServer server = BammBamm.instance().getTlsAlpnServer();
            server.addCertificate(alias, privateKey, cert);
        }
    }

    /**
     * Removes an TLS-ALPN certificate.
     */
    public static class Remove extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String alias = urlParams.get("alias");

            TlsAlpnServer server = BammBamm.instance().getTlsAlpnServer();
            server.removeCertificate(alias);
        }
    }

}
