/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2017 Richard "Shred" Körber
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

import org.shredzone.acme4j.it.server.TlsSniServer;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;

/**
 * Request handler for all {@code tls-sni-02} related requests.
 */
public final class TlsSniHandler {

    public static final String ADD = "/tlssni/add/:alias";
    public static final String REMOVE = "/tlssni/remove/:alias";

    private TlsSniHandler() {
        // this class cannot be instanciated.
    }

    /**
     * Adds an TLS-SNI certificate.
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

            TlsSniServer server = BammBamm.instance().getTlsSniServer();
            server.addCertificate(alias, privateKey, cert);
        }
    }

    /**
     * Removes an TLS-SNI certificate.
     */
    public static class Remove extends AbstractResponder {
        @Override
        public void handle(Map<String, String> urlParams, IHTTPSession session) throws Exception {
            String alias = urlParams.get("alias");

            TlsSniServer server = BammBamm.instance().getTlsSniServer();
            server.removeCertificate(alias);
        }
    }

}
