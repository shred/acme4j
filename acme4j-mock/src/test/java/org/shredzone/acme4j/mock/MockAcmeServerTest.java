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
package org.shredzone.acme4j.mock;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.util.Optional;

import org.junit.Test;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.mock.connection.MockAcmeProvider;
import org.shredzone.acme4j.mock.controller.Controller;
import org.shredzone.acme4j.mock.controller.KeyChangeController;
import org.shredzone.acme4j.mock.controller.NewAccountController;
import org.shredzone.acme4j.mock.controller.NewAuthzController;
import org.shredzone.acme4j.mock.controller.NewNonceController;
import org.shredzone.acme4j.mock.controller.NewOrderController;
import org.shredzone.acme4j.mock.controller.RevokeCertController;
import org.shredzone.acme4j.mock.model.MockAccount;
import org.shredzone.acme4j.mock.model.MockAuthorization;
import org.shredzone.acme4j.mock.model.MockChallenge;
import org.shredzone.acme4j.mock.model.MockOrder;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link MockAcmeServer}.
 */
public class MockAcmeServerTest {

    /**
     * Test the default constructor.
     */
    @Test
    public void testConstructor() {
        MockAcmeServer server = new MockAcmeServer();

        assertThat(server.getDirectory().getEndpoints().size(), is(6));
        assertEndpoint(server, "newNonce", NewNonceController.class);
        assertEndpoint(server, "newAccount", NewAccountController.class);
        assertEndpoint(server, "newOrder", NewOrderController.class);
        assertEndpoint(server, "revokeCert", RevokeCertController.class);
        assertEndpoint(server, "keyChange", KeyChangeController.class);
        assertEndpoint(server, "newAuthz", NewAuthzController.class);

        assertThat(server.getAccounts(), is(empty()));
        assertThat(server.getDirectory(), not(nullValue()));
        assertThat(server.getRepository(), not(nullValue()));
        assertThat(server.getIdentifiers(), is(empty()));
    }

    /**
     * Test the custom constructor.
     */
    @Test
    public void testCustomConstructor() {
        MockAcmeServer server = new MockAcmeServer(m -> {
            m.remove("newAuthz");
            m.put("custom", new Controller() {});
        });

        assertThat(server.getDirectory().getEndpoints().size(), is(6));
        assertEndpoint(server, "newNonce", NewNonceController.class);
        assertEndpoint(server, "newAccount", NewAccountController.class);
        assertEndpoint(server, "newOrder", NewOrderController.class);
        assertEndpoint(server, "revokeCert", RevokeCertController.class);
        assertEndpoint(server, "keyChange", KeyChangeController.class);
        assertEndpoint(server, "custom", Controller.class);

        assertThat(server.getAccounts(), is(empty()));
        assertThat(server.getDirectory(), not(nullValue()));
        assertThat(server.getRepository(), not(nullValue()));
        assertThat(server.getIdentifiers(), is(empty()));
    }

    /**
     * Test session creation.
     */
    @Test
    public void testSession() {
        MockAcmeServer server = new MockAcmeServer();

        Session session = server.createSession();
        assertThat(session, not(nullValue()));
        assertThat(session.getServerUri(), is(MockAcmeProvider.MOCK_URI));
        assertThat(session.provider(), instanceOf(MockAcmeProvider.class));
    }

    /**
     * Test login creation.
     */
    @Test
    public void testLogin() throws URISyntaxException {
        KeyPair keyPair2 = KeyPairUtils.createKeyPair(1024);

        // Fresh server has no accounts
        MockAcmeServer server = new MockAcmeServer();
        assertThat(server.getAccounts(), is(empty()));

        // Login creates a new account
        Login login1 = server.createLogin();
        assertThat(login1.getKeyPair(), not(nullValue()));
        assertThat(login1.getSession(), not(nullValue()));
        assertThat(server.getAccounts().size(), is(1));
        MockAccount mockAccount1 = server.getAccounts().get(0);
        assertThat(login1.getAccountLocation().toURI(), is(mockAccount1.getLocation().toURI()));

        // Login with new key creates another account
        Login login2 = server.createLogin(keyPair2);
        assertThat(login2.getKeyPair(), not(nullValue()));
        assertThat(login2.getSession(), not(nullValue()));
        assertThat(server.getAccounts().size(), is(2));
        MockAccount mockAccount2 = server.getAccounts().get(1);
        assertThat(login2.getAccountLocation().toURI(), is(mockAccount2.getLocation().toURI()));

        // Login with same key returns same account
        Login login3 = server.createLogin(keyPair2);
        assertThat(server.getAccounts().size(), is(2));
        assertThat(login3.getAccountLocation().toURI(), is(login2.getAccountLocation().toURI()));
    }

    /**
     * Test account handling.
     */
    @Test
    public void testAccount() {
        KeyPair keyPair1 = KeyPairUtils.createKeyPair(1024);
        KeyPair keyPair2 = KeyPairUtils.createKeyPair(1024);

        MockAcmeServer server = new MockAcmeServer();
        assertThat(server.getAccounts(), is(empty()));
        assertThat(server.findAccount(keyPair1.getPublic()).isPresent(), is(false));
        assertThat(server.findAccount(keyPair2.getPublic()).isPresent(), is(false));

        MockAccount account1 = server.createAccount(keyPair1.getPublic());
        assertThat(server.getAccounts().size(), is(1));
        assertThat(server.findAccount(keyPair1.getPublic()).isPresent(), is(true));
        assertThat(server.findAccount(keyPair2.getPublic()).isPresent(), is(false));

        MockAccount account2 = server.createAccount(keyPair2.getPublic());
        assertThat(server.getAccounts().size(), is(2));
        assertThat(server.findAccount(keyPair1.getPublic()).isPresent(), is(true));
        assertThat(server.findAccount(keyPair2.getPublic()).isPresent(), is(true));

        assertThat(server.findAccount(keyPair1.getPublic()).get(), is(account1));
        assertThat(server.findAccount(keyPair2.getPublic()).get(), is(account2));

        try {
            server.createAccount(keyPair2.getPublic());
            fail("Could create another account with the same key");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        account1.setStatus(Status.INVALID);
        assertThat(server.getAccounts().size(), is(2));
        assertThat(server.findAccount(keyPair1.getPublic()).isPresent(), is(false));
        assertThat(server.findAccount(keyPair2.getPublic()).isPresent(), is(true));

        account2.setStatus(Status.INVALID);
        assertThat(server.getAccounts().size(), is(2));
        assertThat(server.findAccount(keyPair1.getPublic()).isPresent(), is(false));
        assertThat(server.findAccount(keyPair2.getPublic()).isPresent(), is(false));
    }

    /**
     * Test authorization handling.
     */
    @Test
    public void testAuthorization() {
        Identifier identifier = Identifier.dns("example.org");

        MockAcmeServer server = new MockAcmeServer();

        assertThat(server.getIdentifiers(), is(empty()));

        MockAuthorization auth = server.createAuthorization(identifier);
        assertThat(auth, not(nullValue()));
        assertThat(server.getIdentifiers().size(), is(1));
        assertThat(server.getIdentifiers(), contains(identifier));
        assertThat(auth.getIdentifier(), is(identifier));

        Optional<MockAuthorization> foundAuth = server.findAuthorization(identifier);
        assertThat(foundAuth.isPresent(), is(true));
        assertThat(foundAuth.get(), sameInstance(auth));

        MockAuthorization auth2 = server.createAuthorization(identifier);
        assertThat(server.getIdentifiers().size(), is(1));
        assertThat(auth2, sameInstance(auth));

        Optional<MockAuthorization> missingAuth = server.findAuthorization(Identifier.dns("example.com"));
        assertThat(missingAuth.isPresent(), is(false));
    }

    /**
     * Test creation and fetching of {@link MockAccount}.
     */
    @Test
    public void testCreateFetchAccount() {
        KeyPair keyPair = KeyPairUtils.createKeyPair(1024);

        MockAcmeServer server = new MockAcmeServer();
        MockAccount createdAccount = server.createAccount(keyPair.getPublic());
        assertThat(createdAccount, not(nullValue()));

        Login login = server.createLogin(keyPair);
        Account account = login.getAccount();
        MockAccount mockAccount = server.getMockOf(account);
        assertThat(mockAccount, sameInstance(createdAccount));
    }

    /**
     * Test creation and fetching of {@link MockAuthorization}.
     */
    @Test
    public void testCreateFetchAuthorization() {
        Identifier identifier = Identifier.dns("example.com");

        MockAcmeServer server = new MockAcmeServer();
        MockAuthorization createdAuth = server.createAuthorization(identifier);
        assertThat(createdAuth, not(nullValue()));

        Login login = server.createLogin();
        Authorization auth = login.bindAuthorization(createdAuth.getLocation());
        MockAuthorization mockAuth = server.getMockOf(auth);
        assertThat(mockAuth, sameInstance(createdAuth));
    }

    /**
     * Test creation and fetching of {@link MockChallenge}.
     */
    @Test
    public void testCreateFetchChallenge() {
        MockAcmeServer server = new MockAcmeServer();
        MockChallenge createdChallenge = server.createChallenge(Http01Challenge.TYPE);
        assertThat(createdChallenge, not(nullValue()));

        MockAuthorization createdAuth = server.createAuthorization(Identifier.dns("example.com"));
        createdAuth.getChallenges().add(createdChallenge);

        Login login = server.createLogin();
        Authorization auth = login.bindAuthorization(createdAuth.getLocation());
        Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        assertThat(challenge, not(nullValue()));

        MockChallenge mockChallenge = server.getMockOf(challenge);
        assertThat(mockChallenge, sameInstance(createdChallenge));
    }

    /**
     * Test creation and fetching of {@link MockOrder}.
     */
    @Test
    public void testCreateFetchOrder() {
        MockAcmeServer server = new MockAcmeServer();

        MockOrder createdOrder = server.createOrder(Identifier.dns("example.com"));
        assertThat(createdOrder, not(nullValue()));

        Login login = server.createLogin();
        Order order = login.bindOrder(createdOrder.getLocation());
        MockOrder mockOrder = server.getMockOf(order);
        assertThat(mockOrder, sameInstance(createdOrder));
    }

    /**
     * Assert that an endpoint is defined in the directory.
     *
     * @param server
     *         {@link MockAcmeServer} to test
     * @param type
     *         Endpoint name
     * @param expectedType
     *         Expected {@link Controller} type
     */
    private void assertEndpoint(MockAcmeServer server, String type, Class<? extends Controller> expectedType) {
        URL endpointUrl = server.getDirectory().getEndpoints().get(type);
        assertThat(endpointUrl, not(nullValue()));

        Optional<Controller> controller = server.getRepository().getController(endpointUrl);
        assertThat(controller.isPresent(), is(true));
        assertThat(controller.get(), is(instanceOf(expectedType)));
    }

}
