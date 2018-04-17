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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

/**
 * A BammBamm client.
 */
@ParametersAreNonnullByDefault
public class BammBammClient {
    private final String baseUrl;

    /**
     * Creates a new BammBamm client.
     *
     * @param baseUrl
     *            Base URL of the BammBamm server to connect to.
     */
    public BammBammClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Adds a HTTP token.
     *
     * @param token
     *            Token to add
     * @param challenge
     *            Challenge to respond with
     */
    public void httpAddToken(String token, String challenge) throws IOException {
        createRequest(HttpHandler.ADD)
                .arg(":token", token)
                .param("challenge", challenge)
                .submit();
    }

    /**
     * Removes a HTTP token.
     *
     * @param token
     *            Token to remove
     */
    public void httpRemoveToken(String token) throws IOException {
        createRequest(HttpHandler.REMOVE)
                .arg(":token", token)
                .submit();
    }

    /**
     * Adds an A Record to the DNS. Only one A Record is supported per domain. If another
     * A Record is set, it will replace the existing one.
     *
     * @param domain
     *            Domain of the A Record
     * @param ip
     *            IP address or domain name. If a domain name is used, it will be resolved
     *            and the IP will be used.
     */
    public void dnsAddARecord(String domain, String ip) throws IOException {
        createRequest(DnsHandler.ADD_A_RECORD)
                .arg(":domain", domain)
                .param("ip", ip)
                .submit();
    }

    /**
     * Removes an A Record from the DNS.
     *
     * @param domain
     *            Domain to remove the A Record from
     */
    public void dnsRemoveARecord(String domain) throws IOException {
        createRequest(DnsHandler.REMOVE_A_RECORD)
                .arg(":domain", domain)
                .submit();
    }

    /**
     * Adds a TXT Record to the DNS. Only one TXT Record is supported per domain. If
     * another TXT Record is set, it will replace the existing one.
     *
     * @param domain
     *            Domain to add the TXT Record to
     * @param txt
     *            TXT record to add
     */
    public void dnsAddTxtRecord(String domain, String txt) throws IOException {
        createRequest(DnsHandler.ADD_TXT_RECORD)
                .arg(":domain", domain)
                .param("txt", txt)
                .submit();
    }

    /**
     * Removes a TXT Record from the DNS.
     *
     * @param domain
     *            Domain to remove the TXT Record from
     */
    public void dnsRemoveTxtRecord(String domain) throws IOException {
        createRequest(DnsHandler.REMOVE_TXT_RECORD)
                .arg(":domain", domain)
                .submit();
    }

    /**
     * Adds a certificate for TLS-ALPN tests.
     *
     * @param alias
     *            An alias to be used for removal, for example the domain name being
     *            validated.
     * @param privateKey
     *            {@link PrivateKey} of the certificate
     * @param cert
     *            {@link X509Certificate} containing the domain name to respond to
     */
    public void tlsAlpnAddCertificate(String alias, PrivateKey privateKey, X509Certificate cert) throws IOException {
        try {
            createRequest(TlsAlpnHandler.ADD)
                    .arg(":alias", alias)
                    .param("privateKey", privateKey.getEncoded())
                    .param("cert", cert.getEncoded())
                    .submit();
        } catch (CertificateEncodingException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Removes a certificate.
     *
     * @param alias
     *            Certificate alias to remove
     */
    public void tlsAlpnRemoveCertificate(String alias) throws IOException {
        createRequest(TlsAlpnHandler.REMOVE)
                .arg(":alias", alias)
                .submit();
    }

    /**
     * Creates a new {@link Request} object.
     *
     * @param call
     *            Path to be called
     * @return Created {@link Request} object
     */
    private Request createRequest(String call) {
        return new Request(baseUrl, call);
    }

    /**
     * This class helps to assemble and invoke a HTTP POST request.
     */
    @ParametersAreNonnullByDefault
    private static class Request {
        private static final HttpClient CLIENT = HttpClients.createDefault();
        private static final Encoder BASE64 = Base64.getEncoder();
        private static final Charset UTF8 = Charset.forName("utf-8");

        private final List<NameValuePair> params = new ArrayList<>();
        private final String baseUrl;
        private String call;

        /**
         * Creates a new {@link Request}.
         *
         * @param baseUrl
         *            Base URL of the server to invoke
         * @param call
         *            Path to invoke. It may contain placeholders.
         */
        public Request(String baseUrl, String call) {
            this.baseUrl = baseUrl;
            this.call = call;
        }

        /**
         * Sets a path parameter.
         *
         * @param key
         *            Placeholder to change, leading ':' inclusive!
         * @param value
         *            Value of the parameter
         * @return itself
         */
        public Request arg(String key, String value) {
            try {
                call = call.replace(key, URLEncoder.encode(value, UTF8.name()));
            } catch (UnsupportedEncodingException ex) {
                throw new InternalError("utf-8 missing", ex);
            }
            return this;
        }

        /**
         * Adds a form parameter. It will be sent in the request body.
         *
         * @param key
         *            Parameter name
         * @param value
         *            Parameter value
         * @return itself
         */
        public Request param(String key, String value) {
            params.add(new BasicNameValuePair(key, value));
            return this;
        }

        /**
         * Adds a binary form parameter. It will be sent in the request body.
         *
         * @param key
         *            Parameter name
         * @param value
         *            Parameter value. It will be Base64 encoded.
         * @return itself
         */
        public Request param(String key, byte[] value) {
            return param(key, BASE64.encodeToString(value));
        }

        /**
         * Submits the POST request.
         */
        public void submit() throws IOException {
            try {
                HttpPost httppost = new HttpPost(baseUrl + call);
                if (!params.isEmpty()) {
                    httppost.setEntity(new UrlEncodedFormEntity(params, UTF8));
                }
                HttpResponse response = CLIENT.execute(httppost);

                EntityUtils.consume(response.getEntity());

                if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                    throw new IOException(response.getStatusLine().getReasonPhrase());
                }
            } catch (ClientProtocolException ex) {
                throw new IOException(ex);
            }
        }
    }

}
