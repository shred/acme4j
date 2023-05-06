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
package org.shredzone.acme4j.it.pebble;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * Session related integration tests.
 */
public class SessionIT extends PebbleITBase {

    @Test
    public void testResources() throws AcmeException {
        var session = new Session(pebbleURI());

        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_ACCOUNT));
        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_NONCE));
        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_ORDER));
    }

    @Test
    public void testMetadata() throws AcmeException {
        var session = new Session(pebbleURI());

        var meta = session.getMetadata();
        assertThat(meta).isNotNull();

        assertThat(meta.getTermsOfService().orElseThrow())
                .isEqualTo(URI.create("data:text/plain,Do%20what%20thou%20wilt"));
        assertThat(meta.getWebsite()).isEmpty();
        assertThat(meta.getCaaIdentities()).isEmpty();
        assertThatJson(meta.getJSON().toString()).isEqualTo("{"
                        + "'termsOfService': 'data:text/plain,Do%20what%20thou%20wilt',"
                        + "'externalAccountRequired': false"
                        + "}");
    }

}
