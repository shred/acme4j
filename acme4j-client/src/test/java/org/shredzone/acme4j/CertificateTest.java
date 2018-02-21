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
package org.shredzone.acme4j;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Certificate}.
 */
public class CertificateTest {

    private URL resourceUrl = url("http://example.com/acme/resource");
    private URL locationUrl = url("http://example.com/acme/certificate");

    /**
     * Test that a certificate can be downloaded.
     */
    @Test
    public void testDownload() throws Exception {
        final List<X509Certificate> originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public List<X509Certificate> readCertificates() throws AcmeException {
                return originalCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation, is("alternate"));
                return Arrays.asList(
                        url("https://example.com/acme/alt-cert/1"),
                        url("https://example.com/acme/alt-cert/2"));
            }
        };

        Certificate cert = new Certificate(provider.createLogin(), locationUrl);
        cert.download();

        X509Certificate downloadedCert = cert.getCertificate();
        assertThat(downloadedCert.getEncoded(), is(originalCert.get(0).getEncoded()));

        List<X509Certificate> downloadedChain = cert.getCertificateChain();
        assertThat(downloadedChain.size(), is(originalCert.size()));
        for (int ix = 0; ix < downloadedChain.size(); ix++) {
            assertThat(downloadedChain.get(ix).getEncoded(), is(originalCert.get(ix).getEncoded()));
        }

        byte[] writtenPem;
        byte[] originalPem;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                OutputStreamWriter w = new OutputStreamWriter(baos)) {
            cert.writeCertificate(w);
            w.flush();
            writtenPem = baos.toByteArray();
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InputStream in = getClass().getResourceAsStream("/cert.pem")) {
            int len;
            byte[] buffer = new byte[2048];
            while((len = in.read(buffer)) >= 0) {
                baos.write(buffer, 0, len);
            }
            originalPem = baos.toByteArray();
        }
        assertThat(writtenPem, is(originalPem));

        assertThat(cert.getAlternates(), is(notNullValue()));
        assertThat(cert.getAlternates().size(), is(2));
        assertThat(cert.getAlternates().get(0), is(url("https://example.com/acme/alt-cert/1")));
        assertThat(cert.getAlternates().get(1), is(url("https://example.com/acme/alt-cert/2")));

        provider.close();
    }

    /**
     * Test that a certificate can be revoked.
     */
    @Test
    public void testRevokeCertificate() throws AcmeException, IOException {
        final List<X509Certificate> originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean certRequested = false;

            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
                assertThat(session, is(notNullValue()));
                certRequested = true;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("revokeCertificateRequest").toString()));
                assertThat(session, is(notNullValue()));
                assertThat(keypair, is(notNullValue()));
                certRequested = false;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() throws AcmeException {
                assertThat(certRequested, is(true));
                return originalCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation, is("alternate"));
                return Collections.emptyList();
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Certificate cert = new Certificate(provider.createLogin(), locationUrl);
        cert.revoke();

        provider.close();
    }

    /**
     * Test that a certificate can be revoked with reason.
     */
    @Test
    public void testRevokeCertificateWithReason() throws AcmeException, IOException {
        final List<X509Certificate> originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean certRequested = false;

            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
                assertThat(session, is(notNullValue()));
                certRequested = true;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("revokeCertificateWithReasonRequest").toString()));
                assertThat(session, is(notNullValue()));
                assertThat(keypair, is(notNullValue()));
                certRequested = false;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() throws AcmeException {
                assertThat(certRequested, is(true));
                return originalCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation, is("alternate"));
                return Collections.emptyList();
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Certificate cert = new Certificate(provider.createLogin(), locationUrl);
        cert.revoke(RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

    /**
     * Test that numeric revocation reasons are correctly translated.
     */
    @Test
    public void testRevocationReason() {
        assertThat(RevocationReason.code(1), is(RevocationReason.KEY_COMPROMISE));
    }

    /**
     * Test that a certificate can be revoked by its domain key pair.
     */
    @Test
    public void testRevokeCertificateByKeyPair() throws AcmeException, IOException {
        final List<X509Certificate> originalCert = TestUtils.createCertificate();
        final KeyPair certKeyPair = TestUtils.createDomainKeyPair();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJSON("revokeCertificateWithReasonRequest").toString()));
                assertThat(session, is(notNullValue()));
                assertThat(keypair, is(certKeyPair));
                return HttpURLConnection.HTTP_OK;
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Session session = provider.createSession();

        Certificate.revoke(session, certKeyPair, originalCert.get(0), RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

}
