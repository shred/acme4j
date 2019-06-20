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

import static java.util.Objects.requireNonNull;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.mock.connection.MockAcmeProvider;
import org.shredzone.acme4j.mock.connection.MockCertificateAuthority;
import org.shredzone.acme4j.mock.connection.MockConnection;
import org.shredzone.acme4j.mock.connection.NoncePool;
import org.shredzone.acme4j.mock.connection.Repository;
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
import org.shredzone.acme4j.mock.model.MockDirectory;
import org.shredzone.acme4j.mock.model.MockOrder;

/**
 * This is the heart of acme4j unit testing. A {@link MockAcmeServer} simulates a simple
 * ACME server, and offers methods to check and amend the server's state.
 * <p>
 * <em>Important:</em> This is a very simple ACME server simulation. Its main purpose is
 * to provide a simple mean to unit test acme4j clients. It most likely does not behave
 * like a real ACME server. It is strongly recommended to run additional integration
 * tests, e.g. against the <a href="https://github.com/letsencrypt/pebble">Pebble</a>
 * test server.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class MockAcmeServer {
    private final NoncePool noncePool = new NoncePool();
    private final Repository repository = new Repository();
    private final MockCertificateAuthority ca = new MockCertificateAuthority();
    private final List<MockAccount> accounts = new ArrayList<>();
    private final Map<Identifier, MockAuthorization> authorizations = new HashMap<>();
    private final MockDirectory directory;
    private final MockAcmeProvider provider;

    /**
     * Constructs a new {@link MockAcmeServer} instance.
     */
    public MockAcmeServer() {
        this(null);
    }

    /**
     * Constructs a new {@link MockAcmeServer} instance.
     *
     * @param modifier
     *         This {@link Consumer} is invoked after a map of directory types and
     *         controller instances have been created. It can make amends to this map,
     *         adding further types, or removing unwanted types. @{code null} to leave
     *         the map unchanged.
     */
    public MockAcmeServer(@Nullable Consumer<Map<String, Controller>> modifier) {
        Map<String, Controller> typeMap = new HashMap<>();
        typeMap.put("newNonce", new NewNonceController(this));
        typeMap.put("newAccount", new NewAccountController(this));
        typeMap.put("newOrder", new NewOrderController(this));
        typeMap.put("revokeCert", new RevokeCertController(this));
        typeMap.put("keyChange", new KeyChangeController(this));
        typeMap.put("newAuthz", new NewAuthzController(this));
        if (modifier != null) {
            modifier.accept(typeMap);
        }
        directory = MockDirectory.create(repository, typeMap);
        provider = new MockAcmeProvider(directory.getLocation(),
                u -> new MockConnection(repository, noncePool));
    }

    /**
     * Creates a new {@link Session} for accessing this {@link MockAcmeServer}.
     * <p>
     * This is the only way to create a {@link Session} to this server!
     */
    public Session createSession() {
        return new Session(MockAcmeProvider.MOCK_URI, provider);
    }

    /**
     * Creates a {@link Login} to a new empty account with a random key pair.
     * <p>
     * The generated key pair is available via {@link Login#getKeyPair()}.
     * <p>
     * The key pair is generated by {@link java.security.SecureRandom}. Depending on the
     * underlying operating system, this call may block when the entropy pool is
     * exhausted. If you create a lot of new {@link MockAcmeServer} instances, you should
     * consider to generate a single global {@link KeyPair} for all of your tests, and use
     * {@link #createLogin(KeyPair)} instead.
     * <p>
     * The {@link Session} of this login is available via {@link Login#getSession()}.
     *
     * @return Login to that account
     */
    public Login createLogin() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            return createLogin(keyGen.generateKeyPair());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Creates a {@link Login} to the account with the given {@link KeyPair}.
     * <p>
     * If there is no such account, a new dummy account will be created automatically.
     * <p>
     * The {@link Session} of this login is available via {@link Login#getSession()}.
     *
     * @param keyPair
     *         Account's {@link KeyPair}
     * @return Login to that account
     */
    public Login createLogin(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        MockAccount account = findAccount(publicKey)
                .orElseGet(() -> createAccount(publicKey));
        return createSession().login(account.getLocation(), keyPair);
    }

    /**
     * Returns the {@link MockDirectory} instance of this server.
     */
    public MockDirectory getDirectory() {
        return directory;
    }

    /**
     * Returns a list of all {@link MockAccount} currently registered to this connection.
     * The list also contains deactivated and revoked accounts.
     */
    public List<MockAccount> getAccounts() {
        return Collections.unmodifiableList(accounts);
    }

    /**
     * Returns a set of all {@link Identifier} known to this server.
     */
    public Set<Identifier> getIdentifiers() {
        return Collections.unmodifiableSet(authorizations.keySet());
    }

    /**
     * Returns the {@link Repository} of this ACME server. The repository is used to resolve
     * all URLs known to this server, and manages the {@link Controller} instances that
     * are used for handling requests to these URLs.
     * <p>
     * The {@link Repository} may be useful for some very rare test cases. For example, it
     * is possible to change the behavior of single {@link Controller} instances by
     * {@link Repository#wrapController(URL, Function)}.
     */
    public Repository getRepository() {
        return repository;
    }

    /**
     * Returns the {@link MockCertificateAuthority} of this server. It is used for signing
     * certificates.
     */
    public MockCertificateAuthority getCertificateAuthority() {
        return ca;
    }

    /**
     * Creates a new account.
     *
     * @param publicKey
     *         {@link PublicKey} of the new account. Creation will fail if an account with
     *         this key has already been created before.
     * @return The {@link MockAccount} that was created
     */
    public MockAccount createAccount(PublicKey publicKey) {
        if (findAccount(publicKey).isPresent()) {
            throw new IllegalArgumentException("An account with that public key is already present");
        }

        MockAccount account = MockAccount.create(getRepository(), publicKey);
        accounts.add(account);
        return account;
    }

    /**
     * Finds the {@link MockAccount} with the given key. Accounts that are not having a
     * {@link Status#VALID} status will be ignored.
     *
     * @param key
     *         {@link PublicKey} of the account
     * @return Valid {@link MockAccount} with that {@link PublicKey}
     */
    public Optional<MockAccount> findAccount(PublicKey key) {
        byte[] encoded = key.getEncoded();
        return accounts.stream()
                .filter(a -> a.getStatus() == Status.VALID)
                .filter(a -> Arrays.equals(a.getPublicKey().getEncoded(), encoded))
                .findFirst();
    }

    /**
     * Creates a new {@link MockAuthorization} for the given {@link Identifier}. If there
     * is already a {@link MockAuthorization} for that {@link Identifier}, it is returned
     * instead.
     *
     * @param identifier
     *         {@link Identifier} to create a {@link MockAuthorization} for.
     * @return The {@link MockAuthorization} that is used for authorizing the given {@link
     * Identifier}
     */
    public MockAuthorization createAuthorization(Identifier identifier) {
        return authorizations.computeIfAbsent(identifier, i -> MockAuthorization.create(repository, i));
    }

    /**
     * Finds a {@link MockAuthorization} that authorizes the given {@link Identifier}.
     *
     * @param identifier
     *         {@link Identifier} to find the {@link MockAuthorization} for
     * @return The {@link MockAuthorization} that authorizes the given {@link Identifier}
     */
    public Optional<MockAuthorization> findAuthorization(Identifier identifier) {
        return Optional.ofNullable(authorizations.get(identifier));
    }

    /**
     * Creates a new {@link MockChallenge} instance of the given type.
     *
     * @param type
     *         Challenge type (e.g. {@value org.shredzone.acme4j.challenge.Http01Challenge#TYPE}).
     * @return The {@link MockChallenge} instance that was created
     */
    public MockChallenge createChallenge(String type) {
        requireNonNull(type, "type");
        return MockChallenge.create(repository, type);
    }

    /**
     * Creates a new {@link MockOrder} for the given {@link Identifier}.
     * <p>
     * This method also automatically generates all necessary {@link MockAuthorization}
     * objects.
     *
     * @param identifiers
     *         One or more {@link Identifier} to order a certificate for.
     * @return The {@link MockOrder} instance that was created
     */
    public MockOrder createOrder(Identifier... identifiers) {
        return createOrder(Arrays.asList(identifiers));
    }

    /**
     * Creates a new {@link MockOrder} for the given set of {@link Identifier}.
     * <p>
     * This method also automatically generates all necessary {@link MockAuthorization}
     * objects.
     *
     * @param identifiers
     *         Collection of {@link Identifier} to order a certificate for. Must contain
     *         at least one identifier. {@code null} values are ignored.
     * @return The {@link MockOrder} instance that was created
     */
    public MockOrder createOrder(Collection<Identifier> identifiers) {
        List<MockAuthorization> authz = identifiers.stream()
                .filter(Objects::nonNull)
                .map(this::createAuthorization)
                .collect(Collectors.toList());

        return createOrder(identifiers, authz);
    }

    /**
     * Creates a new {@link MockOrder} for the given set of {@link Identifier}.
     * <p>
     * This method also accepts a set of {@link MockAuthorization} that are necessary for
     * the order. Use this method if the required set of authorizations do not match the
     * set of identifiers.
     *
     * @param identifiers
     *         Collection of {@link Identifier} to order a certificate for.
     * @param authorizations
     *         Collection of {@link MockAuthorization} that need to be resolved before the
     *         order can be finalized.
     * @return The {@link MockOrder} instance that was created
     */
    public MockOrder createOrder(Collection<Identifier> identifiers, Collection<MockAuthorization> authorizations) {
        if (identifiers == null || identifiers.isEmpty()) {
            throw new IllegalArgumentException("Requires at least one identifier");
        }
        if (authorizations == null || authorizations.isEmpty()) {
            throw new IllegalArgumentException("Requires at least one authorization");
        }

        return MockOrder.create(repository, identifiers, authorizations, ca);
    }

    /**
     * Returns the {@link MockAccount} that corresponds to the given {@link Account}.
     *
     * @param account
     *         {@link Account} to get the matching {@link MockAccount} for
     * @return MockAccount
     * @throws NoSuchElementException
     *         if there is no such mock resource
     */
    public MockAccount getMockOf(Account account) {
        return repository.getResourceOfType(account.getLocation(), MockAccount.class)
                .orElseThrow(() -> new NoSuchElementException("Unknown account " + account.getLocation()));
    }

    /**
     * Returns the {@link MockAuthorization} that corresponds to the given {@link
     * Authorization}.
     *
     * @param authorization
     *         {@link Authorization} to get the matching {@link MockAuthorization} for
     * @return MockAuthorization
     * @throws NoSuchElementException
     *         if there is no such mock resource
     */
    public MockAuthorization getMockOf(Authorization authorization) {
        return repository.getResourceOfType(authorization.getLocation(), MockAuthorization.class)
                .orElseThrow(() -> new NoSuchElementException("Unknown authorization " + authorization.getLocation()));
    }

    /**
     * Returns the {@link MockChallenge} that corresponds to the given {@link Challenge}.
     *
     * @param challenge
     *         {@link Challenge} to get the matching {@link MockChallenge} for
     * @return MockChallenge
     * @throws NoSuchElementException
     *         if there is no such mock resource
     */
    public MockChallenge getMockOf(Challenge challenge) {
        return repository.getResourceOfType(challenge.getLocation(), MockChallenge.class)
                .orElseThrow(() -> new NoSuchElementException("Unknown challenge " + challenge.getLocation()));
    }

    /**
     * Returns the {@link MockOrder} that corresponds to the given {@link Order}.
     *
     * @param order
     *         {@link Order} to get the matching {@link MockOrder} for
     * @return MockOrder
     * @throws NoSuchElementException
     *         if there is no such mock resource
     */
    public MockOrder getMockOf(Order order) {
        return repository.getResourceOfType(order.getLocation(), MockOrder.class)
                .orElseThrow(() -> new NoSuchElementException("Unknown order " + order.getLocation()));
    }

    /**
     * Tests if the given nonce was issued by this server and is valid.
     *
     * @param nonce
     *         Nonce to test
     * @return {@code true} if the nonce is valid and was issued by this server
     */
    public boolean isValidNonce(@Nullable String nonce) {
        return nonce != null && noncePool.isValidNonce(nonce);
    }

}
