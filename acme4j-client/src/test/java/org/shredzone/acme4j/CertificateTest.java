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

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.shredzone.acme4j.toolbox.TestUtils.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.TestableConnectionProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link Certificate}.
 */
public class CertificateTest {

    private final URL resourceUrl = url("http://example.com/acme/resource");
    private final URL locationUrl = url("http://example.com/acme/certificate");
    private final URL alternate1Url = url("https://example.com/acme/alt-cert/1");
    private final URL alternate2Url = url("https://example.com/acme/alt-cert/2");

    /**
     * Test that a certificate can be downloaded.
     */
    @Test
    public void testDownload() throws Exception {
        var originalCert = TestUtils.createCertificate("/cert.pem");
        var alternateCert = TestUtils.createCertificate("/certid-cert.pem");

        var provider = new TestableConnectionProvider() {
            List<X509Certificate> sendCert;

            @Override
            public int sendCertificateRequest(URL url, Login login) {
                assertThat(url).isIn(locationUrl, alternate1Url, alternate2Url);
                assertThat(login).isNotNull();
                if (locationUrl.equals(url)) {
                    sendCert = originalCert;
                } else {
                    sendCert = alternateCert;
                }
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() {
                return sendCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation).isEqualTo("alternate");
                return Arrays.asList(alternate1Url, alternate2Url);
            }
        };

        var cert = new Certificate(provider.createLogin(), locationUrl);
        cert.download();

        var downloadedCert = cert.getCertificate();
        assertThat(downloadedCert.getEncoded()).isEqualTo(originalCert.get(0).getEncoded());

        var downloadedChain = cert.getCertificateChain();
        assertThat(downloadedChain).hasSize(originalCert.size());
        for (var ix = 0; ix < downloadedChain.size(); ix++) {
            assertThat(downloadedChain.get(ix).getEncoded()).isEqualTo(originalCert.get(ix).getEncoded());
        }

        byte[] writtenPem;
        byte[] originalPem;
        try (var baos = new ByteArrayOutputStream(); var w = new OutputStreamWriter(baos)) {
            cert.writeCertificate(w);
            w.flush();
            writtenPem = baos.toByteArray();
        }
        try (var baos = new ByteArrayOutputStream(); var in = getClass().getResourceAsStream("/cert.pem")) {
            int len;
            var buffer = new byte[2048];
            while((len = in.read(buffer)) >= 0) {
                baos.write(buffer, 0, len);
            }
            originalPem = baos.toByteArray();
        }
        assertThat(writtenPem).isEqualTo(originalPem);

        assertThat(cert.isIssuedBy("The ACME CA X1")).isFalse();
        assertThat(cert.isIssuedBy(CERT_ISSUER)).isTrue();

        assertThat(cert.getAlternates()).isNotNull();
        assertThat(cert.getAlternates()).hasSize(2);
        assertThat(cert.getAlternates()).element(0).isEqualTo(alternate1Url);
        assertThat(cert.getAlternates()).element(1).isEqualTo(alternate2Url);

        assertThat(cert.getAlternateCertificates()).isNotNull();
        assertThat(cert.getAlternateCertificates()).hasSize(2);
        assertThat(cert.getAlternateCertificates())
                .element(0)
                .extracting(Certificate::getLocation)
                .isEqualTo(alternate1Url);
        assertThat(cert.getAlternateCertificates())
                .element(1)
                .extracting(Certificate::getLocation)
                .isEqualTo(alternate2Url);

        assertThat(cert.findCertificate("The ACME CA X1")).
                isEmpty();
        assertThat(cert.findCertificate(CERT_ISSUER).orElseThrow())
                .isSameAs(cert);
        assertThat(cert.findCertificate("minica root ca 3a1356").orElseThrow())
                .isSameAs(cert.getAlternateCertificates().get(0));
        assertThat(cert.getAlternateCertificates().get(0).isIssuedBy("minica root ca 3a1356"))
                .isTrue();

        provider.close();
    }

    /**
     * Test that a certificate can be revoked.
     */
    @Test
    public void testRevokeCertificate() throws AcmeException, IOException {
        var originalCert = TestUtils.createCertificate("/cert.pem");

        var provider = new TestableConnectionProvider() {
            private boolean certRequested = false;

            @Override
            public int sendCertificateRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                certRequested = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("revokeCertificateRequest").toString());
                assertThat(login).isNotNull();
                certRequested = false;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() {
                assertThat(certRequested).isTrue();
                return originalCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation).isEqualTo("alternate");
                return Collections.emptyList();
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        var cert = new Certificate(provider.createLogin(), locationUrl);
        cert.revoke();

        provider.close();
    }

    /**
     * Test that a certificate can be revoked with reason.
     */
    @Test
    public void testRevokeCertificateWithReason() throws AcmeException, IOException {
        var originalCert = TestUtils.createCertificate("/cert.pem");

        var provider = new TestableConnectionProvider() {
            private boolean certRequested = false;

            @Override
            public int sendCertificateRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                certRequested = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("revokeCertificateWithReasonRequest").toString());
                assertThat(login).isNotNull();
                certRequested = false;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() {
                assertThat(certRequested).isTrue();
                return originalCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                assertThat(relation).isEqualTo("alternate");
                return Collections.emptyList();
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        var cert = new Certificate(provider.createLogin(), locationUrl);
        cert.revoke(RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

    /**
     * Test that numeric revocation reasons are correctly translated.
     */
    @Test
    public void testRevocationReason() {
        assertThat(RevocationReason.code(1))
                .isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    /**
     * Test that a certificate can be revoked by its domain key pair.
     */
    @Test
    public void testRevokeCertificateByKeyPair() throws AcmeException, IOException {
        var originalCert = TestUtils.createCertificate("/cert.pem");
        var certKeyPair = TestUtils.createDomainKeyPair();

        var provider = new TestableConnectionProvider() {
            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Session session, KeyPair keypair) {
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("revokeCertificateWithReasonRequest").toString());
                assertThat(session).isNotNull();
                assertThat(keypair).isEqualTo(certKeyPair);
                return HttpURLConnection.HTTP_OK;
            }
        };

        provider.putTestResource(Resource.REVOKE_CERT, resourceUrl);

        var session = provider.createSession();

        Certificate.revoke(session, certKeyPair, originalCert.get(0), RevocationReason.KEY_COMPROMISE);

        provider.close();
    }

    /**
     * Test that RenewalInfo is returned.
     */
    @Test
    public void testRenewalInfo() throws AcmeException, IOException {
        // certid-cert.pem and certId provided by ACME ARI specs and known good
        var certId = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";
        var certIdCert = TestUtils.createCertificate("/certid-cert.pem");
        var certResourceUrl = URI.create(resourceUrl.toExternalForm() + "/" + certId).toURL();
        var retryAfterInstant = Instant.now().plus(10L, ChronoUnit.DAYS);

        var provider = new TestableConnectionProvider() {
            private boolean certRequested = false;
            private boolean infoRequested = false;

            @Override
            public int sendCertificateRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                certRequested = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendRequest(URL url, Session session, ZonedDateTime ifModifiedSince) {
                assertThat(url).isEqualTo(certResourceUrl);
                assertThat(session).isNotNull();
                assertThat(ifModifiedSince).isNull();
                infoRequested = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public JSON readJsonResponse() {
                assertThat(infoRequested).isTrue();
                return getJSON("renewalInfo");
            }

            @Override
            public List<X509Certificate> readCertificates() {
                assertThat(certRequested).isTrue();
                return certIdCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                return Collections.emptyList();
            }

            @Override
            public Optional<Instant> getRetryAfter() {
                return Optional.of(retryAfterInstant);
            }
        };

        provider.putTestResource(Resource.RENEWAL_INFO, resourceUrl);

        var cert = new Certificate(provider.createLogin(), locationUrl);
        assertThat(cert.hasRenewalInfo()).isTrue();
        assertThat(cert.getRenewalInfoLocation())
                .hasValue(certResourceUrl);

        var renewalInfo = cert.getRenewalInfo();
        assertThat(renewalInfo.getRetryAfter())
                .isEmpty();
        assertThat(renewalInfo.getSuggestedWindowStart())
                .isEqualTo("2021-01-03T00:00:00Z");
        assertThat(renewalInfo.getSuggestedWindowEnd())
                .isEqualTo("2021-01-07T00:00:00Z");
        assertThat(renewalInfo.getExplanation())
                .isNotEmpty()
                .contains(url("https://example.com/docs/example-mass-reissuance-event"));

        assertThat(renewalInfo.fetch()).hasValue(retryAfterInstant);
        assertThat(renewalInfo.getRetryAfter()).hasValue(retryAfterInstant);

        provider.close();
    }

    /**
     * Test that a certificate is marked as replaced.
     */
    @Test
    public void testMarkedAsReplaced() throws AcmeException, IOException {
        // certid-cert.pem and certId provided by ACME ARI specs and known good
        var certId = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";
        var certIdCert = TestUtils.createCertificate("/certid-cert.pem");
        var certResourceUrl = URI.create(resourceUrl.toExternalForm() + "/" + certId).toURL();

        var provider = new TestableConnectionProvider() {
            private boolean certRequested = false;

            @Override
            public int sendCertificateRequest(URL url, Login login) {
                assertThat(url).isEqualTo(locationUrl);
                assertThat(login).isNotNull();
                certRequested = true;
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public int sendSignedRequest(URL url, JSONBuilder claims, Login login) {
                assertThat(certRequested).isTrue();
                assertThat(url).isEqualTo(resourceUrl);
                assertThatJson(claims.toString()).isEqualTo(getJSON("replacedCertificateRequest").toString());
                assertThat(login).isNotNull();
                return HttpURLConnection.HTTP_OK;
            }

            @Override
            public List<X509Certificate> readCertificates() {
                assertThat(certRequested).isTrue();
                return certIdCert;
            }

            @Override
            public Collection<URL> getLinks(String relation) {
                return Collections.emptyList();
            }
        };

        provider.putTestResource(Resource.RENEWAL_INFO, resourceUrl);

        var cert = new Certificate(provider.createLogin(), locationUrl);
        assertThat(cert.hasRenewalInfo()).isTrue();
        assertThat(cert.getRenewalInfoLocation()).hasValue(certResourceUrl);

        provider.close();
    }

}
