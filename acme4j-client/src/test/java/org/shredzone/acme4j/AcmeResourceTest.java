/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;

import org.junit.Test;
import org.shredzone.acme4j.toolbox.TestUtils;

/**
 * Unit tests for {@link AcmeResource}.
 */
public class AcmeResourceTest {

    /**
     * Test constructors and setters
     */
    @Test
    public void testConstructor() throws Exception {
        Login login = TestUtils.login();
        URL location = new URL("http://example.com/acme/resource");

        try {
            new DummyResource(null, null);
            fail("Could create resource without login and location");
        } catch (NullPointerException ex) {
            // expected
        }

        AcmeResource resource = new DummyResource(login, location);
        assertThat(resource.getLogin(), is(login));
        assertThat(resource.getLocation(), is(location));
    }

    /**
     * Test if {@link AcmeResource} is properly serialized.
     */
    @Test
    public void testSerialization() throws Exception {
        Login login = TestUtils.login();
        URL location = new URL("http://example.com/acme/resource");

        // Create a Challenge for testing
        DummyResource challenge = new DummyResource(login, location);
        assertThat(challenge.getLogin(), is(login));

        // Serialize it
        byte[] serialized;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
                out.writeObject(challenge);
            }
            serialized = baos.toByteArray();
        }

        // Make sure there is no PrivateKey in the stream
        String str = new String(serialized, "iso-8859-1");
        if (str.contains("Ljava/security/PrivateKey")) {
            fail("serialized stream contains a PrivateKey");
        }

        // Deserialize to new object
        DummyResource restored;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
                ObjectInputStream in = new ObjectInputStream(bais)) {
            Object obj = in.readObject();
            assertThat(obj, instanceOf(DummyResource.class));
            restored = (DummyResource) obj;
        }
        assertThat(restored, not(sameInstance(challenge)));

        // Make sure the restored object is not attached to a login
        try {
            restored.getLogin();
            fail("was able to retrieve a session");
        } catch (IllegalStateException ex) {
            // must fail because we don't have a login in the restored object
        }

        // Rebind to login
        restored.rebind(login);

        // Make sure the new login is set
        assertThat(restored.getLogin(), is(login));
    }

    /**
     * Test if a rebind attempt fails.
     */
    @Test(expected = IllegalStateException.class)
    public void testRebind() throws Exception {
        Login login = TestUtils.login();
        URL location = new URL("http://example.com/acme/resource");

        AcmeResource resource = new DummyResource(login, location);
        assertThat(resource.getLogin(), is(login));

        Login login2 = TestUtils.login();
        resource.rebind(login2); // fails to rebind to another login
    }

    /**
     * Minimum implementation of {@link AcmeResource}.
     */
    private static class DummyResource extends AcmeResource {
        private static final long serialVersionUID = 7188822681353082472L;
        public DummyResource(Login login, URL location) {
            super(login, location);
        }
    }

}
