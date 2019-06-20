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

import org.junit.Test;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.mock.connection.ProblemBuilder;
import org.shredzone.acme4j.mock.connection.Repository;
import org.shredzone.acme4j.mock.controller.ChallengeController;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link MockChallenge}.
 */
public class MockChallengeTest {

    /**
     * Test creation and default values.
     */
    @Test
    public void testCreate() {
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);

        // Check locations
        assertThat(challenge.getUniqueId(), not(emptyOrNullString()));
        assertThat(challenge.getLocation().toString(),
                is("https://acme.test/challenge/" + challenge.getUniqueId()));

        // Controllers were added to the repository?
        assertThat(repository.getController(challenge.getLocation()).get(),
                is(instanceOf(ChallengeController.class)));
        assertThat(repository.getResourceOfType(challenge.getLocation(), MockChallenge.class).get(),
                is(sameInstance(challenge)));

        // Default values
        assertThat(challenge.getData(), is(anEmptyMap()));
        assertThat(challenge.getError(), is(nullValue()));
        assertThat(challenge.getStatus(), is(Status.PENDING));
        assertThat(challenge.getToken(), is(nullValue()));
        assertThat(challenge.getType(), is(Http01Challenge.TYPE));
        assertThat(challenge.getValidated(), is(nullValue()));
    }

    /**
     * Test setters and JSON generation.
     */
    @Test
    public void testSettersAndJson() {
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);
        Instant now = Instant.now();
        Problem problem = new ProblemBuilder(challenge.getLocation()).error("connection").build();

        challenge.setStatus(Status.INVALID);
        challenge.setToken("abc123");
        challenge.setValidated(now);
        challenge.setError(problem);
        challenge.getData().put("foo", 123);

        assertThat(challenge.getStatus(), is(Status.INVALID));
        assertThat(challenge.getToken(), is("abc123"));
        assertThat(challenge.getValidated(), is(now));
        assertThat(challenge.getError(), is(problem));
        assertThat(challenge.getData().get("foo"), is(123));

        JSONBuilder jb = new JSONBuilder();
        jb.put("type", Http01Challenge.TYPE);
        jb.put("url", challenge.getLocation());
        jb.put("status", "invalid");
        jb.put("validated", now);
        jb.put("token", "abc123");
        jb.put("error", problem.asJSON().toMap());
        jb.put("foo", 123);
        assertThat(challenge.toJSON().toString(), sameJSONAs(jb.toString()));
    }

    /**
     * Test automatic status.
     */
    @Test
    public void testAutoStatus() {
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);

        assertThat(challenge.getStatus(), is(Status.PENDING));

        challenge.setError(new ProblemBuilder(challenge.getLocation()).error("connection").build());
        assertThat(challenge.getStatus(), is(Status.INVALID));
        challenge.setError(null);

        challenge.setValidated(Instant.now());
        assertThat(challenge.getStatus(), is(Status.VALID));

        challenge.setStatus(Status.UNKNOWN);
        assertThat(challenge.getStatus(), is(Status.UNKNOWN));
    }

    /**
     * Test random token generation.
     */
    @Test
    public void testRandomToken() {
        Repository repository = new Repository();
        MockChallenge challenge = MockChallenge.create(repository, Http01Challenge.TYPE);

        assertThat(challenge.getToken(), is(emptyOrNullString()));

        challenge.setRandomToken();
        assertThat(challenge.getToken(), not(emptyOrNullString()));

        String token1 = challenge.getToken();
        challenge.setRandomToken();
        assertThat(challenge.getToken(), not(emptyOrNullString()));
        assertThat(challenge.getToken(), not(token1));
    }

}