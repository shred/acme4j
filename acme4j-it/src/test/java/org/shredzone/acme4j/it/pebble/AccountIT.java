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
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;

/**
 * Account related integration tests.
 */
public class AccountIT extends PebbleITBase {

    /**
     * Create a new account, then bind it to a second session.
     */
    @Test
    public void testCreate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        // Register a new user
        Login login = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session);

        URL location = login.getAccountLocation();
        assertIsPebbleUrl(location);

        // Check registered data
        Account acct = login.getAccount();
        assertThat(acct.getLocation(), is(location));
        assertThat(acct.getContacts(), contains(URI.create("mailto:acme@example.com")));
        assertThat(acct.getStatus(), is(Status.VALID));

        // Bind another Account object
        Session session2 = new Session(pebbleURI());
        Login login2 = new Login(location, keyPair, session2);
        assertThat(login2.getAccountLocation(), is(location));
        Account acct2 = login2.getAccount();
        assertThat(acct2.getLocation(), is(location));
        assertThat(acct2.getContacts(), contains(URI.create("mailto:acme@example.com")));
        assertThat(acct2.getStatus(), is(Status.VALID));
    }

    /**
     * Register the same key pair twice.
     */
    @Test
    public void testReCreate() throws AcmeException {
        KeyPair keyPair = createKeyPair();

        // Register a new user
        Session session1 = new Session(pebbleURI());
        Login login1 = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session1);

        URL location1 = login1.getAccountLocation();
        assertIsPebbleUrl(location1);

        // Try to register the same account again
        Session session2 = new Session(pebbleURI());
        Login login2 = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session2);

        URL location2 = login2.getAccountLocation();
        assertIsPebbleUrl(location2);

        assertThat(location1, is(location2));
    }

    /**
     * Create a new account. Locate it via onlyExisting.
     */
    @Test
    public void testCreateOnlyExisting() throws AcmeException {
        KeyPair keyPair = createKeyPair();

        Session session1 = new Session(pebbleURI());
        Login login1 = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session1);

        URL location1 = login1.getAccountLocation();
        assertIsPebbleUrl(location1);

        Session session2 = new Session(pebbleURI());
        Login login2 = new AccountBuilder()
                        .onlyExisting()
                        .useKeyPair(keyPair)
                        .createLogin(session2);

        URL location2 = login2.getAccountLocation();
        assertIsPebbleUrl(location2);

        assertThat(location1, is(location2));
    }

    /**
     * Locate a non-existing account via onlyExisting. Make sure an accountDoesNotExist
     * error is returned.
     */
    @Test
    public void testNotExisting() throws AcmeException {
        try {
            KeyPair keyPair = createKeyPair();
            Session session = new Session(pebbleURI());
            new AccountBuilder().onlyExisting().useKeyPair(keyPair).create(session);
            fail("onlyExisting flag was ignored");
        } catch (AcmeServerException ex) {
            assertThat(ex.getType(), is(URI.create("urn:ietf:params:acme:error:accountDoesNotExist")));
        }
    }

    /**
     * Modify the contacts of an account.
     */
    @Test
    public void testModify() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        Account acct = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
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

    /**
     * Change the account key.
     */
    @Test
    @Ignore // TODO PEBBLE: missing
    public void testKeyChange() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        Account acct = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
        URL location = acct.getLocation();

        KeyPair newKeyPair = createKeyPair();
        acct.changeKey(newKeyPair);

        try {
            Session sessionOldKey = new Session(pebbleURI());
            Account oldAccount = sessionOldKey.login(location, keyPair).getAccount();
            oldAccount.update();
        } catch (AcmeUnauthorizedException ex) {
            // Expected
        }

        Session sessionNewKey = new Session(pebbleURI());
        Account newAccount = sessionNewKey.login(location, newKeyPair).getAccount();
        assertThat(newAccount.getStatus(), is(Status.VALID));
    }

    /**
     * Deactivate an account.
     */
    @Test
    public void testDeactivate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI());

        Account acct = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
        URL location = acct.getLocation();

        acct.deactivate();

        // Make sure it is deactivated now...
        assertThat(acct.getStatus(), is(Status.DEACTIVATED));

        // Make sure account cannot be accessed any more...
        try {
            Session session2 = new Session(pebbleURI());
            Account acct2 = session2.login(location, keyPair).getAccount();
            acct2.update();
            fail("Account can still be accessed");
        } catch (AcmeUnauthorizedException ex) {
            assertThat(ex.getMessage(), is("Account has been deactivated"));
        }
    }

}
