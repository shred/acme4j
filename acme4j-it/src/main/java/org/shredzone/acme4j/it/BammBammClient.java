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
import java.util.Arrays;
import java.util.Objects;

import javax.annotation.ParametersAreNonnullByDefault;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * The BammBamm client connects to the pebble-challtestsrv.
 */
@ParametersAreNonnullByDefault
public class BammBammClient {
    private static final HttpClient CLIENT = HttpClients.createDefault();

    private final String baseUrl;

    /**
     * Creates a new BammBamm client.
     *
     * @param baseUrl
     *            Base URL of the pebble-challtestsrv server to connect to.
     */
    public BammBammClient(String baseUrl) {
        this.baseUrl = Objects.requireNonNull(baseUrl) + '/';
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
        JSONBuilder jb = new JSONBuilder();
        jb.put("token", token);
        jb.put("content", challenge);
        sendRequest("add-http01", jb.toString());
    }

    /**
     * Removes a HTTP token.
     *
     * @param token
     *            Token to remove
     */
    public void httpRemoveToken(String token) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("token", token);
        sendRequest("del-http01", jb.toString());
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
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        jb.array("addresses", Arrays.asList(ip));
        sendRequest("add-a", jb.toString());
    }

    /**
     * Removes an A Record from the DNS.
     *
     * @param domain
     *            Domain to remove the A Record from
     */
    public void dnsRemoveARecord(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        sendRequest("clear-a", jb.toString());
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
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain + '.');
        jb.put("value", txt);
        sendRequest("set-txt", jb.toString());
    }

    /**
     * Removes a TXT Record from the DNS.
     *
     * @param domain
     *            Domain to remove the TXT Record from
     */
    public void dnsRemoveTxtRecord(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain + '.');
        sendRequest("clear-txt", jb.toString());
    }

    /**
     * Adds a CNAME Record to the DNS. Only one CNAME Record is supported per domain. If
     * another CNAME Record is set, it will replace the existing one.
     *
     * @param domain
     *         Domain to add the CNAME Record to
     * @param cname
     *         CNAME Record to add
     * @since 2.9
     */
    public void dnsAddCnameRecord(String domain, String cname) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        jb.put("target", cname);
        sendRequest("set-cname", jb.toString());
    }

    /**
     * Removes a CNAME Record from the DNS.
     *
     * @param domain
     *         Domain to remove the CNAME Record from
     * @since 2.9
     */
    public void dnsRemoveCnameRecord(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        sendRequest("clear-cname", jb.toString());
    }

    /**
     * Simulates a SERVFAIL for the given domain.
     *
     * @param domain
     *         Domain that will give a SERVFAIL response
     * @since 2.9
     */
    public void dnsAddServFailRecord(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        sendRequest("set-servfail", jb.toString());
    }

    /**
     * Removes a SERVFAIL Record from the DNS.
     *
     * @param domain
     *         Domain to remove the SEVFAIL Record from
     * @since 2.9
     */
    public void dnsRemoveServFailRecord(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        sendRequest("clear-servfail", jb.toString());
    }

    /**
     * Adds a certificate for TLS-ALPN tests.
     *
     * @param domain
     *            Certificate domain to be added
     * @param keyauth
     *            Key authorization to be used for validation
     */
    public void tlsAlpnAddCertificate(String domain, String keyauth) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        jb.put("content", keyauth);
        sendRequest("add-tlsalpn01", jb.toString());
    }

    /**
     * Removes a certificate.
     *
     * @param domain
     *            Certificate domain to be removed
     */
    public void tlsAlpnRemoveCertificate(String domain) throws IOException {
        JSONBuilder jb = new JSONBuilder();
        jb.put("host", domain);
        sendRequest("del-tlsalpn01", jb.toString());
    }

    /**
     * Sends a request to the pebble-challtestsrv.
     *
     * @param call
     *            Endpoint to be called
     * @param body
     *            JSON body
     */
    private void sendRequest(String call, String body) throws IOException {
        try {
            HttpPost httppost = new HttpPost(baseUrl + call);
            httppost.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));

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
