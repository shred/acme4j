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
import static org.junit.Assert.*;
import static org.shredzone.acme4j.toolbox.TestUtils.*;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import org.junit.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Certificate}.
 */
public class CertificateTest {

    private URL resourceUrl = url("http://example.com/acme/resource");
    private URL locationUrl = url("http://example.com/acme/certificate");
    private URL chainUrl    = url("http://example.com/acme/chain");

    /**
     * Test that a certificate can be downloaded.
     */
    @Test
    public void testDownload() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            private boolean isLocationUrl;

            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, isOneOf(locationUrl, chainUrl));
                isLocationUrl = url.equals(locationUrl);
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                if (isLocationUrl) {
                    // The leaf certificate, might be asynchronous
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                            HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                } else {
                    // The root certificate chain, always OK
                    assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                            HttpURLConnection.HTTP_OK));
                }
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public X509Certificate readCertificate() {
                return originalCert;
            }

            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                // Just do nothing
            }

            @Override
            public URL getLink(String relation) {
                switch(relation) {
                    case "up": return (isLocationUrl ? chainUrl : null);
                    default: return null;
                }
            }
        };

        Certificate cert = new Certificate(provider.createSession(), locationUrl);
        X509Certificate downloadedCert = cert.download();
        assertThat(downloadedCert, is(sameInstance(originalCert)));
        assertThat(cert.getChainLocation(), is(chainUrl));

        X509Certificate[] downloadedChain = cert.downloadChain();
        assertThat(downloadedChain.length, is(1));
        assertThat(downloadedChain[0], is(sameInstance(originalCert)));

        // Make sure the chain array is a local copy
        downloadedChain[0] = null;
        X509Certificate[] downloadedChain2 = cert.downloadChain();
        assertThat(downloadedChain2[0], is(sameInstance(originalCert)));

        provider.close();
    }

    /**
     * Test that a {@link AcmeRetryAfterException} is thrown.
     */
    @Test
    public void testRetryAfter() throws AcmeException, IOException {
        final Instant retryAfter = Instant.now().plus(Duration.ofSeconds(30));

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendRequest(URL url, Session session) {
                assertThat(url, is(locationUrl));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(
                        HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_ACCEPTED));
                return HttpURLConnection.HTTP_ACCEPTED;
            }


            @Override
            public void handleRetryAfter(String message) throws AcmeException {
                throw new AcmeRetryAfterException(message, retryAfter);
            }
        };

        Certificate cert = new Certificate(provider.createSession(), locationUrl);

        try {
            cert.download();
            fail("Expected AcmeRetryAfterException");
        } catch (AcmeRetryAfterException ex) {
            assertThat(ex.getRetryAfter(), is(retryAfter));
        }

        provider.close();
    }

    /**
     * Test that a certificate can be revoked.
     */
    @Test
    public void testRevokeCertificate() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJson("revokeCertificateRequest")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Certificate cert = new Certificate(provider.createSession(), locationUrl, null, originalCert);
        cert.revoke();

        provider.close();
    }

    /**
     * Test that a certificate can be revoked with reason.
     */
    @Test
    public void testRevokeCertificateWithReason() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJson("revokeCertificateWithReasonRequest")));
                assertThat(session, is(notNullValue()));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Certificate cert = new Certificate(provider.createSession(), locationUrl, null, originalCert);
        cert.revoke(RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

    /**
     * Test that a certificate can be revoked by its domain key pair.
     */
    @Test
    public void testRevokeCertificateByKeyPair() throws AcmeException, IOException {
        final X509Certificate originalCert = TestUtils.createCertificate();
        final KeyPair certKeyPair = TestUtils.createDomainKeyPair();

        TestableConnectionProvider provider = new TestableConnectionProvider() {
            @Override
            public void sendSignedRequest(URL url, JSONBuilder claims, Session session) {
                assertThat(url, is(resourceUrl));
                assertThat(claims.toString(), sameJSONAs(getJson("revokeCertificateWithReasonRequest")));
                assertThat(session, is(notNullValue()));
                assertThat(session.getKeyPair(), is(certKeyPair));
            }

            @Override
            public int accept(int... httpStatus) throws AcmeException {
                assertThat(httpStatus, isIntArrayContainingInAnyOrder(HttpURLConnection.HTTP_OK));
                return HttpURLConnection.HTTP_OK;
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        Session session = provider.createSession();
        session.setKeyPair(certKeyPair);

        Certificate.revoke(session, originalCert, RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

    /**
     * Test that numeric revocation reasons are correctly translated.
     */
    @Test
    public void testRevocationReason() {
        assertThat(RevocationReason.code(1), is(RevocationReason.KEY_COMPROMISE));
    }

}
