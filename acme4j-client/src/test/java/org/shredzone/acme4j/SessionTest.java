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
package org.shredzone.acme4j;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.shredzone.acme4j.toolbox.TestUtils.*;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Locale;

import org.assertj.core.api.AutoCloseableSoftAssertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.provider.GenericAcmeProvider;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit test for {@link Session}.
 */
public class SessionTest {

    /**
     * Test constructor
     */
    @Test
    public void testConstructor() {
        var serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        assertThrows(NullPointerException.class, () -> new Session((URI) null));

        var session = new Session(serverUri);
        assertThat(session).isNotNull();
        assertThat(session.getServerUri()).isEqualTo(serverUri);

        var session2 = new Session(TestUtils.ACME_SERVER_URI);
        assertThat(session2).isNotNull();
        assertThat(session2.getServerUri()).isEqualTo(serverUri);

        var session3 = new Session(serverUri, new GenericAcmeProvider());
        assertThat(session3).isNotNull();
        assertThat(session3.getServerUri()).isEqualTo(serverUri);

        assertThrows(IllegalArgumentException.class,
                () -> new Session("#*aBaDuRi*#"),
                "Bad URI in constructor");
        assertThrows(IllegalArgumentException.class,
                () -> new Session(URI.create("acme://invalid"), new GenericAcmeProvider()),
                "Unsupported URI");
    }

    /**
     * Test getters and setters.
     */
    @Test
    public void testGettersAndSetters() {
        var serverUri = URI.create(TestUtils.ACME_SERVER_URI);
        var now = ZonedDateTime.now();

        var session = new Session(serverUri);

        assertThat(session.getNonce()).isNull();
        session.setNonce(DUMMY_NONCE);
        assertThat(session.getNonce()).isEqualTo(DUMMY_NONCE);

        assertThat(session.getServerUri()).isEqualTo(serverUri);
        assertThat(session.networkSettings()).isNotNull();

        assertThat(session.getDirectoryExpires()).isNull();
        session.setDirectoryExpires(now);
        assertThat(session.getDirectoryExpires()).isEqualTo(now);
        session.setDirectoryExpires(null);
        assertThat(session.getDirectoryExpires()).isNull();

        assertThat(session.getDirectoryLastModified()).isNull();
        session.setDirectoryLastModified(now);
        assertThat(session.getDirectoryLastModified()).isEqualTo(now);
        session.setDirectoryLastModified(null);
        assertThat(session.getDirectoryLastModified()).isNull();
    }

    /**
     * Test login methods.
     */
    @Test
    public void testLogin() throws IOException {
        var serverUri = URI.create(TestUtils.ACME_SERVER_URI);
        var accountLocation = url(TestUtils.ACCOUNT_URL);
        var accountKeyPair = TestUtils.createKeyPair();

        var session = new Session(serverUri);

        var login = session.login(accountLocation, accountKeyPair);
        assertThat(login).isNotNull();
        assertThat(login.getSession()).isEqualTo(session);
        assertThat(login.getAccountLocation()).isEqualTo(accountLocation);
        assertThat(login.getKeyPair()).isEqualTo(accountKeyPair);
    }

    /**
     * Test that the directory is properly read.
     */
    @Test
    public void testDirectory() throws AcmeException, IOException {
        var serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        var mockProvider = mock(AcmeProvider.class);
        when(mockProvider.directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(serverUri)))
                .thenReturn(getJSON("directory"));

        var session = new Session(serverUri) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            }
        };

        // No directory has been fetched yet
        assertThat(session.hasDirectory()).isFalse();

        assertThat(session.resourceUrl(Resource.NEW_ACCOUNT))
                .isEqualTo(new URL("https://example.com/acme/new-account"));

        // There is a local copy of the directory now
        assertThat(session.hasDirectory()).isTrue();

        assertThat(session.resourceUrl(Resource.NEW_AUTHZ))
                .isEqualTo(new URL("https://example.com/acme/new-authz"));
        assertThat(session.resourceUrl(Resource.NEW_ORDER))
                .isEqualTo(new URL("https://example.com/acme/new-order"));

        assertThrows(AcmeException.class, () -> session.resourceUrl(Resource.REVOKE_CERT));

        var meta = session.getMetadata();
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(meta).isNotNull();
            softly.assertThat(meta.getTermsOfService())
                    .isEqualTo(URI.create("https://example.com/acme/terms"));
            softly.assertThat(meta.getWebsite()).isEqualTo(url("https://www.example.com/"));
            softly.assertThat(meta.getCaaIdentities()).containsExactlyInAnyOrder("example.com");
            softly.assertThat(meta.isAutoRenewalEnabled()).isTrue();
            softly.assertThat(meta.getAutoRenewalMaxDuration()).isEqualTo(Duration.ofDays(365));
            softly.assertThat(meta.getAutoRenewalMinLifetime()).isEqualTo(Duration.ofHours(24));
            softly.assertThat(meta.isAutoRenewalGetAllowed()).isTrue();
            softly.assertThat(meta.isExternalAccountRequired()).isTrue();
            softly.assertThat(meta.getJSON()).isNotNull();
        }

        // Make sure directory is read
        verify(mockProvider, atLeastOnce()).directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.any(URI.class));
    }

    /**
     * Test that the directory is properly read even if there are no metadata.
     */
    @Test
    public void testNoMeta() throws AcmeException, IOException {
        var serverUri = URI.create(TestUtils.ACME_SERVER_URI);

        var mockProvider = mock(AcmeProvider.class);
        when(mockProvider.directory(
                        ArgumentMatchers.any(Session.class),
                        ArgumentMatchers.eq(serverUri)))
                .thenReturn(getJSON("directoryNoMeta"));

        var session = new Session(serverUri) {
            @Override
            public AcmeProvider provider() {
                return mockProvider;
            }
        };

        assertThat(session.resourceUrl(Resource.NEW_ACCOUNT))
                .isEqualTo(new URL("https://example.com/acme/new-account"));
        assertThat(session.resourceUrl(Resource.NEW_AUTHZ))
                .isEqualTo(new URL("https://example.com/acme/new-authz"));
        assertThat(session.resourceUrl(Resource.NEW_ORDER))
                .isEqualTo(new URL("https://example.com/acme/new-order"));

        var meta = session.getMetadata();
        try (var softly = new AutoCloseableSoftAssertions()) {
            softly.assertThat(meta).isNotNull();
            softly.assertThat(meta.getTermsOfService()).isNull();
            softly.assertThat(meta.getWebsite()).isNull();
            softly.assertThat(meta.getCaaIdentities()).isEmpty();
            softly.assertThat(meta.isAutoRenewalEnabled()).isFalse();
            softly.assertThat(meta.getAutoRenewalMaxDuration()).isNull();
            softly.assertThat(meta.getAutoRenewalMinLifetime()).isNull();
            softly.assertThat(meta.isAutoRenewalGetAllowed()).isFalse();
        }
    }

    /**
     * Test that the locale is properly set.
     */
    @Test
    public void testLocale() {
        var session = new Session(URI.create(TestUtils.ACME_SERVER_URI));

        // default configuration
        assertThat(session.getLocale())
                .isEqualTo(Locale.getDefault());
        assertThat(session.getLanguageHeader())
                .isEqualTo(AcmeUtils.localeToLanguageHeader(Locale.getDefault()));

        // null
        session.setLocale(null);
        assertThat(session.getLocale()).isNull();
        assertThat(session.getLanguageHeader()).isEqualTo("*");

        // a locale
        session.setLocale(Locale.CANADA_FRENCH);
        assertThat(session.getLocale()).isEqualTo(Locale.CANADA_FRENCH);
        assertThat(session.getLanguageHeader()).isEqualTo("fr-CA,fr;q=0.8,*;q=0.1");
    }

}
