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
package org.shredzone.acme4j.mock.model;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static uk.co.datumedge.hamcrest.json.SameJSONAs.sameJSONAs;

import java.time.Instant;
import java.util.Collections;

import org.junit.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.AuthorizationController;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link MockAuthorization}.
 */
public class MockAuthorizationTest {
    private static final Identifier IDENTIFIER = Identifier.dns("example.org");

    /**
     * Test creation and default values.
     */
    @Test
    public void testCreate() {
        Repository repository = new Repository();
        MockAuthorization auth = MockAuthorization.create(repository, IDENTIFIER);

        // Check locations
        assertThat(auth.getUniqueId(), not(emptyOrNullString()));
        assertThat(auth.getLocation().toString(),
                is("https://acme.test/authz/" + auth.getUniqueId()));

        // Controllers were added to the repository?
        assertThat(repository.getController(auth.getLocation()).get(),
                is(instanceOf(AuthorizationController.class)));
        assertThat(repository.getResourceOfType(auth.getLocation(), MockAuthorization.class).get(),
                is(sameInstance(auth)));

        // Default values
        assertThat(auth.getChallenges(), is(empty()));
        assertThat(auth.getExpires(), is(nullValue()));
        assertThat(auth.getIdentifier(), is(IDENTIFIER));
        assertThat(auth.getStatus(), is(Status.PENDING));
        assertThat(auth.getWildcard(), is(nullValue()));

        // Detach from repository
        auth.detach(repository);
        assertThat(repository.getController(auth.getLocation()).isPresent(),
                is(false));
        assertThat(repository.getResourceOfType(auth.getLocation(), MockAuthorization.class).isPresent(),
                is(false));
    }

    /**
     * Test setters and JSON generation.
     */
    @Test
    public void testSettersAndJson() {
        Instant now = Instant.now();
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);
        MockAuthorization auth = MockAuthorization.create(repository, IDENTIFIER);

        auth.setStatus(Status.INVALID);
        auth.setExpires(now);
        auth.setWildcard(false);
        auth.getChallenges().add(challenge);

        assertThat(auth.getStatus(), is(Status.INVALID));
        assertThat(auth.getExpires(), is(now));
        assertThat(auth.getWildcard(), is(false));
        assertThat(auth.getChallenges(), contains(challenge));

        JSONBuilder jb = new JSONBuilder();
        jb.put("identifier", IDENTIFIER.toMap());
        jb.put("status", "invalid");
        jb.put("expires", now);
        jb.array("challenges", Collections.singleton(challenge.toJSON().toMap()));
        // "wildcard" must not be present because it is false
        assertThat(auth.toJSON().toString(), sameJSONAs(jb.toString()));

        auth.setWildcard(true);
        assertThat(auth.getWildcard(), is(true));
        jb.put("wildcard", true);
        assertThat(auth.toJSON().toString(), sameJSONAs(jb.toString()));
    }

    /**
     * Test automatic status.
     */
    @Test
    public void testAutoStatus() {
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);
        MockAuthorization auth = MockAuthorization.create(repository, IDENTIFIER);

        assertThat(auth.getStatus(), is(Status.PENDING));

        auth.setExpires(Instant.now().minusSeconds(10));
        assertThat(auth.getStatus(), is(Status.EXPIRED));
        auth.setExpires(null);

        auth.getChallenges().add(challenge);
        assertThat(auth.getStatus(), is(Status.PENDING));
        challenge.setStatus(Status.VALID);
        assertThat(auth.getStatus(), is(Status.VALID));
        challenge.setStatus(Status.INVALID);
        assertThat(auth.getStatus(), is(Status.INVALID));

        auth.setStatus(Status.UNKNOWN);
        assertThat(auth.getStatus(), is(Status.UNKNOWN));
    }

}