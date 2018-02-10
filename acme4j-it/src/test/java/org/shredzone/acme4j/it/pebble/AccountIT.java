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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;

import org.junit.Ignore;
import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;

/**
 * Account related integration tests.
 */
public class AccountIT extends PebbleITBase {

    @Test
    public void testCreate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        // Register a new user
        AccountBuilder ab = new AccountBuilder();
        ab.addContact("mailto:acme@example.com");
        ab.agreeToTermsOfService();

        Account acct = ab.create(session);
        URL location = acct.getLocation();
        assertIsPebbleUrl(location);
        assertThat(session.getKeyIdentifier(), is(location.toString()));

        // Check registered data
        assertThat(acct.getContacts(), contains(URI.create("mailto:acme@example.com")));
        assertThat(acct.getStatus(), is(Status.VALID));

        // Bind another Account object
        // TODO PEBBLE: Not supported yet
        // Session session2 = new Session(pebbleURI(), keyPair);
        // Account acct2 = Account.bind(session2, location);
        // assertThat(acct2.getLocation(), is(location));
        // assertThat(acct2.getContacts(), contains(URI.create("mailto:acme@example.com")));
        // assertThat(acct2.getStatus(), is(Status.VALID));
    }

    @Test
    public void testCreateOnlyExisting() throws AcmeException {
        KeyPair keyPair = createKeyPair();

        Session session1 = new Session(pebbleURI(), keyPair);
        Account acct1 = new AccountBuilder()
                        .agreeToTermsOfService()
                        .create(session1);
        URL location1 = acct1.getLocation();
        assertIsPebbleUrl(location1);
        assertThat(session1.getKeyIdentifier(), is(location1.toString()));

        Session session2 = new Session(pebbleURI(), keyPair);
        Account acct2 = new AccountBuilder()
                        .onlyExisting()
                        .create(session2);
        URL location2 = acct2.getLocation();
        assertIsPebbleUrl(location2);
        assertThat(session2.getKeyIdentifier(), is(location2.toString()));

        assertThat(location1, is(location2));
    }

    @Test
    public void testNotExisting() throws AcmeException {
        try {
            KeyPair keyPair = createKeyPair();
            Session session = new Session(pebbleURI(), keyPair);
            new AccountBuilder().onlyExisting().create(session);
            fail("Expected an error");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        }
    }

    @Test
    @Ignore // TODO PEBBLE: missing
    public void testModify() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        AccountBuilder ab = new AccountBuilder();
        ab.addContact("mailto:acme@example.com");
        ab.agreeToTermsOfService();

        Account acct = ab.create(session);
        URL location = acct.getLocation();
        assertIsPebbleUrl(location);

        acct.modify().addContact("mailto:acme2@example.com").commit();

        assertThat(acct.getContacts(), contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com")));

        // Still the same after updating
        acct.update();
        assertThat(acct.getContacts(), contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com")));
    }

    @Test
    @Ignore // TODO PEBBLE: missing
    public void testKeyChange() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Account acct = new AccountBuilder().agreeToTermsOfService().create(session);
        URL location = acct.getLocation();

        KeyPair newKeyPair = createKeyPair();
        acct.changeKey(newKeyPair);

        try {
            Session sessionOldKey = new Session(pebbleURI(), keyPair);
            Account oldAccount = Account.bind(sessionOldKey, location);
            oldAccount.update();
        } catch (AcmeUnauthorizedException ex) {
            // Expected
        }

        Session sessionNewKey = new Session(pebbleURI(), newKeyPair);
        Account newAccount = Account.bind(sessionNewKey, location);
        assertThat(newAccount.getStatus(), is(Status.VALID));
    }

    @Test
    @Ignore // TODO PEBBLE: missing
    public void testDeactivate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Account acct = new AccountBuilder().agreeToTermsOfService().create(session);
        URL location = acct.getLocation();

        acct.deactivate();

        Session session2 = new Session(pebbleURI(), keyPair);
        Account acct2 = Account.bind(session2, location);
        assertThat(acct2.getLocation(), is(location));
        assertThat(acct2.getStatus(), is(Status.DEACTIVATED));
    }

}
