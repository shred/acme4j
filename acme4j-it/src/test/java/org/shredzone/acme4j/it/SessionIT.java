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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.net.URI;
import java.security.KeyPair;

import org.junit.Test;
import org.shredzone.acme4j.Metadata;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * Session related integration tests.
 */
public class SessionIT extends PebbleITBase {

    private final KeyPair keyPair = createKeyPair();

    @Test
    public void testNonce() throws AcmeException {
        Session session = new Session(pebbleURI(), keyPair);

        // No nonce yet on a fresh session
        assertThat(session.getNonce(), is(nullValue()));

        // Request directory, also providing a nonce
        session.getMetadata();

        // A nonce must be set now
        assertThat(session.getNonce(), not(nullValue()));
        assertThat(session.provider(), not(nullValue()));
    }

    @Test
    public void testResources() throws AcmeException {
        Session session = new Session(pebbleURI(), keyPair);

        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_ACCOUNT));
        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_NONCE));
        assertIsPebbleUrl(session.resourceUrl(Resource.NEW_ORDER));
    }

    @Test
    public void testMetadata() throws AcmeException {
        Session session = new Session(pebbleURI(), keyPair);

        Metadata meta = session.getMetadata();
        assertThat(meta, not(nullValue()));

        assertThat(meta.getTermsOfService(), is(URI.create("data:text/plain,Do%20what%20thou%20wilt")));
        assertThat(meta.getWebsite(), is(nullValue()));
        assertThat(meta.getCaaIdentities(), is(empty()));
        assertThat(meta.getJSON().toString(), sameJSONAs("{"
                        + "'termsOfService': 'data:text/plain,Do%20what%20thou%20wilt'"
                        + "}"));
    }

}
