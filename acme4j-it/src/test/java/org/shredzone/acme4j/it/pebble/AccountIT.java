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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
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
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        // Register a new user
        var login = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session);

        var location = login.getAccountLocation();
        assertIsPebbleUrl(location);

        // Check registered data
        var acct = login.getAccount();
        assertThat(acct.getLocation()).isEqualTo(location);
        assertThat(acct.getContacts()).contains(URI.create("mailto:acme@example.com"));
        assertThat(acct.getStatus()).isEqualTo(Status.VALID);

        // Bind another Account object
        var session2 = new Session(pebbleURI());
        var login2 = new Login(location, keyPair, session2);
        assertThat(login2.getAccountLocation()).isEqualTo(location);
        var acct2 = login2.getAccount();
        assertThat(acct2.getLocation()).isEqualTo(location);
        assertThat(acct2.getContacts()).contains(URI.create("mailto:acme@example.com"));
        assertThat(acct2.getStatus()).isEqualTo(Status.VALID);
    }

    /**
     * Register the same key pair twice.
     */
    @Test
    public void testReCreate() throws AcmeException {
        var keyPair = createKeyPair();

        // Register a new user
        var session1 = new Session(pebbleURI());
        var login1 = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session1);

        var location1 = login1.getAccountLocation();
        assertIsPebbleUrl(location1);

        // Try to register the same account again
        var session2 = new Session(pebbleURI());
        var login2 = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session2);

        var location2 = login2.getAccountLocation();
        assertIsPebbleUrl(location2);

        assertThat(location1).isEqualTo(location2);
    }

    /**
     * Create a new account. Locate it via onlyExisting.
     */
    @Test
    public void testCreateOnlyExisting() throws AcmeException {
        var keyPair = createKeyPair();

        var session1 = new Session(pebbleURI());
        var login1 = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .createLogin(session1);

        var location1 = login1.getAccountLocation();
        assertIsPebbleUrl(location1);

        var session2 = new Session(pebbleURI());
        var login2 = new AccountBuilder()
                        .onlyExisting()
                        .useKeyPair(keyPair)
                        .createLogin(session2);

        var location2 = login2.getAccountLocation();
        assertIsPebbleUrl(location2);

        assertThat(location1).isEqualTo(location2);
    }

    /**
     * Locate a non-existing account via onlyExisting. Make sure an accountDoesNotExist
     * error is returned.
     */
    @Test
    public void testNotExisting() {
        var ex = assertThrows(AcmeServerException.class, () -> {
            KeyPair keyPair = createKeyPair();
            Session session = new Session(pebbleURI());
            new AccountBuilder().onlyExisting().useKeyPair(keyPair).create(session);
        });
        assertThat(ex.getType()).isEqualTo(URI.create("urn:ietf:params:acme:error:accountDoesNotExist"));
    }

    /**
     * Modify the contacts of an account.
     */
    @Test
    public void testModify() throws AcmeException {
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        var acct = new AccountBuilder()
                        .addContact("mailto:acme@example.com")
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
        var location = acct.getLocation();
        assertIsPebbleUrl(location);

        acct.modify().addContact("mailto:acme2@example.com").commit();

        assertThat(acct.getContacts()).contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com"));

        // Still the same after updating
        acct.fetch();
        assertThat(acct.getContacts()).contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com"));
    }

    /**
     * Change the account key.
     */
    @Test
    public void testKeyChange() throws AcmeException {
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        var acct = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
        var location = acct.getLocation();

        var newKeyPair = createKeyPair();
        acct.changeKey(newKeyPair);

        assertThrows(AcmeServerException.class, () -> {
            Session sessionOldKey = new Session(pebbleURI());
            Account oldAccount = sessionOldKey.login(location, keyPair).getAccount();
            oldAccount.fetch();
        }, "Old account key is still accessible");

        var sessionNewKey = new Session(pebbleURI());
        var newAccount = sessionNewKey.login(location, newKeyPair).getAccount();
        assertThat(newAccount.getStatus()).isEqualTo(Status.VALID);
    }

    /**
     * Deactivate an account.
     */
    @Test
    public void testDeactivate() throws AcmeException {
        var keyPair = createKeyPair();
        var session = new Session(pebbleURI());

        var acct = new AccountBuilder()
                        .agreeToTermsOfService()
                        .useKeyPair(keyPair)
                        .create(session);
        var location = acct.getLocation();

        acct.deactivate();

        // Make sure it is deactivated now...
        assertThat(acct.getStatus()).isEqualTo(Status.DEACTIVATED);

        // Make sure account cannot be accessed any more...
        var ex = assertThrows(AcmeUnauthorizedException.class,
                () -> {
            Session session2 = new Session(pebbleURI());
            Account acct2 = session2.login(location, keyPair).getAccount();
            acct2.fetch();
        }, "Account can still be accessed");
        assertThat(ex.getMessage()).isEqualTo("Account has been deactivated");
    }

}
