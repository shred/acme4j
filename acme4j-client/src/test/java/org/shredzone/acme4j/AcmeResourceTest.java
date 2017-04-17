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
import org.shredzone.acme4j.util.TestUtils;

/**
 * Unit tests for {@link AcmeResource}.
 */
public class AcmeResourceTest {

    /**
     * Test constructors and setters
     */
    @Test
    public void testConstructor() throws Exception {
        Session session = TestUtils.session();
        URL location = new URL("http://example.com/acme/resource");

        try {
            new DummyResource(null);
            fail("Could create resource without session");
        } catch (NullPointerException ex) {
            // expected
        }

        AcmeResource resource = new DummyResource(session);
        assertThat(resource.getSession(), is(session));

        assertThat(resource.getLocation(), is(nullValue()));
        resource.setLocation(location);
        assertThat(resource.getLocation(), is(location));

        try {
            resource.setLocation(null);
            fail("Could set location to null");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            resource.setSession(null);
            fail("Could set session to null");
        } catch (NullPointerException ex) {
            // expected
        }

        Session session2 = TestUtils.session();
        resource.setSession(session2);
        assertThat(resource.getSession(), is(session2));
    }

    /**
     * Test if {@link AcmeResource} is properly serialized.
     */
    @Test
    public void testSerialization() throws Exception {
        Session session = TestUtils.session();

        // Create a Challenge for testing
        DummyResource challenge = new DummyResource(session);
        assertThat(challenge.getSession(), is(session));

        // Serialize it
        byte[] serialized = null;
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
        DummyResource restored = null;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
                ObjectInputStream in = new ObjectInputStream(bais)) {
            Object obj = in.readObject();
            assertThat(obj, instanceOf(DummyResource.class));
            restored = (DummyResource) obj;
        }
        assertThat(restored, not(sameInstance(challenge)));

        // Make sure the restored object is not attached to a session
        try {
            restored.getSession();
            fail("was able to retrieve a session");
        } catch (IllegalStateException ex) {
            // must fail because we don't have a session in the restored object
        }

        // Set a new session
        restored.setSession(session);

        // Make sure the new session is set
        assertThat(restored.getSession(), is(session));
    }

    /**
     * Test if a rebind attempt fails.
     */
    @Test(expected = IllegalStateException.class)
    public void testRebind() throws Exception {
        Session session = TestUtils.session();
        AcmeResource resource = new DummyResource(session);
        assertThat(resource.getSession(), is(session));

        Session session2 = TestUtils.session();
        resource.rebind(session2); // fails to rebind to another session
    }

    /**
     * Minimum implementation of {@link AcmeResource}.
     */
    private static class DummyResource extends AcmeResource {
        private static final long serialVersionUID = 7188822681353082472L;
        public DummyResource(Session session) {
            super(session);
        }
    }

}
