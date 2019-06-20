/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.example;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.MessageDigest;

import javax.crypto.SecretKey;

import org.jose4j.keys.HmacKey;
import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.MockAcmeServer;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Some examples for testing account operations.
 */
public class AccountTest {

    /**
     * Let's create an account, and find out if it is also present on the mock server.
     */
    @Test
    public void testCreateAccount() throws AcmeException {
        MockAcmeServer server = new MockAcmeServer();
        Session session = server.createSession();

        // Create a new account
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        URI email = URI.create("mailto:foo@example.com");
        Account account = new AccountBuilder()
                .addContact(email)
                .agreeToTermsOfService()
                .useKeyPair(keyPair)
                .create(session);

        // The new account is present at the mock server
        assertThat(server.getAccounts().size(), is(1));

        // The client's account is set up and active
        assertThat(account.getStatus(), is(Status.VALID));
        assertThat(account.getContacts().size(), is(1));
        assertThat(account.getContacts().get(0), is(email));

        // The server's mock account contains the same data
        MockAccount mockAccount = server.getMockOf(account);
        assertThat(mockAccount.getStatus(), is(Status.VALID));
        assertThat(mockAccount.getContacts().size(), is(1));
        assertThat(mockAccount.getContacts().get(0), is(email));

        // The account's and mock account's location is identical
        assertThat(account.getLocation(), is(mockAccount.getLocation()));

        // Create a second account instance
        Account account2 = new AccountBuilder()
                .onlyExisting()
                .useKeyPair(keyPair)
                .create(session);

        // There is still just one account on the server's side
        assertThat(server.getAccounts().size(), is(1));

        // Both accounts share the same location
        assertThat(account2.getLocation(), is(account.getLocation()));
    }

    /**
     * Now let's update an account.
     */
    @Test
    public void testUpdateAccount() throws AcmeException {
        URI email1 = URI.create("mailto:foo@example.com");
        URI email2 = URI.create("mailto:foo-new@example.com");

        MockAcmeServer server = new MockAcmeServer();
        Session session = server.createSession();

        // Create an account with only email1 as contact address
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        Account account = new AccountBuilder()
                .addContact(email1)
                .agreeToTermsOfService()
                .useKeyPair(keyPair)
                .create(session);

        // Modify the account and add a email2 as second contact address
        account.modify().addContact(email2).commit();

        // Our account now contains both addresses
        assertThat(account.getContacts(), containsInAnyOrder(email1, email2));

        // Dito on server side
        MockAccount mockAccount = server.getMockOf(account);
        assertThat(mockAccount.getContacts(), containsInAnyOrder(email1, email2));
    }

    /**
     * Change the account's key pair.
     */
    @Test
    public void testChangeKey() throws AcmeException {
        MockAcmeServer server = new MockAcmeServer();
        Session session = server.createSession();

        // Set up an empty account on server side
        KeyPair oldKeyPair = KeyPairUtils.createKeyPair(1024);
        MockAccount mockAccount = server.createAccount(oldKeyPair.getPublic());
        URL accountLocation = mockAccount.getLocation();

        // Log into this account
        Login login = session.login(accountLocation, oldKeyPair);
        Account account = login.getAccount();

        // Our old account is present
        assertThat(server.findAccount(oldKeyPair.getPublic()).isPresent(), is(true));

        // Change to a new key
        KeyPair newKeyPair = KeyPairUtils.createKeyPair(2048);
        account.changeKey(newKeyPair);

        // The old key is unknown now, the new key is known
        assertThat(server.findAccount(oldKeyPair.getPublic()).isPresent(), is(false));
        assertThat(server.findAccount(newKeyPair.getPublic()).isPresent(), is(true));

        // We can login with the new key, but it's still the old account
        Login newLogin = session.login(accountLocation, newKeyPair);
        assertThat(newLogin.getAccountLocation(), is(account.getLocation()));
    }

    /**
     * Now we are going to deactivate an account.
     */
    @Test
    public void testDeactivateAccount() throws AcmeException {
        MockAcmeServer server = new MockAcmeServer();
        Session session = server.createSession();

        // Set up an empty account on server side
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        MockAccount mockAccount = server.createAccount(keyPair.getPublic());
        URL accountLocation = mockAccount.getLocation();

        // Log into this account
        Login login = session.login(accountLocation, keyPair);
        Account account = login.getAccount();

        // Make sure our account is active
        assertThat(account.getStatus(), is(Status.VALID));
        assertThat(mockAccount.getStatus(), is(Status.VALID));

        // Deactivate it
        account.deactivate();

        // Make sure our account is deactivated now
        assertThat(account.getStatus(), is(Status.DEACTIVATED));
        assertThat(mockAccount.getStatus(), is(Status.DEACTIVATED));
    }

    /**
     * Let's test the External Account Binding.
     */
    @Test
    public void testExternalAccountBinding() throws Exception {
        MockAcmeServer server = new MockAcmeServer();

        // Mark in the directory that external account binding is required
        server.getDirectory().getMetadata().put("externalAccountRequired", true);

        // Create a Session now
        Session session = server.createSession();
        assertThat(session.getMetadata().isExternalAccountRequired(), is(true));

        // Generate the macKey and keyIdentifier
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("Turpentine".getBytes());
        SecretKey macKey = new HmacKey(md.digest());
        String keyIdentifier = "NCC-1701";

        // Create a new account
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        Account account = new AccountBuilder()
                .withKeyIdentifier(keyIdentifier, macKey)
                .useKeyPair(keyPair)
                .create(session);

        // Make sure the account is bound externally on server side...
        MockAccount mockAccount = server.getMockOf(account);
        assertThat(mockAccount.getExternalAccountBinding(), not(nullValue()));

        // ...and client side
        assertThat(account.hasExternalAccountBinding(), is(true));
        assertThat(account.getKeyIdentifier(), is(keyIdentifier));
    }

}
