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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
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
        var login = TestUtils.login();
        var location = new URL("http://example.com/acme/resource");

        assertThrows(NullPointerException.class, () -> new DummyResource(null, null));

        var resource = new DummyResource(login, location);
        assertThat(resource.getLogin()).isEqualTo(login);
        assertThat(resource.getLocation()).isEqualTo(location);
    }

    /**
     * Test if {@link AcmeResource} is properly serialized.
     */
    @Test
    public void testSerialization() throws Exception {
        var login = TestUtils.login();
        var location = new URL("http://example.com/acme/resource");

        // Create a Challenge for testing
        var challenge = new DummyResource(login, location);
        assertThat(challenge.getLogin()).isEqualTo(login);

        // Serialize it
        byte[] serialized;
        try (var baos = new ByteArrayOutputStream()) {
            try (var out = new ObjectOutputStream(baos)) {
                out.writeObject(challenge);
            }
            serialized = baos.toByteArray();
        }

        // Make sure there is no PrivateKey in the stream
        var str = new String(serialized, StandardCharsets.ISO_8859_1);
        assertThat(str).as("serialized stream contains a PrivateKey")
                .doesNotContain("Ljava/security/PrivateKey");

        // Deserialize to new object
        DummyResource restored;
        try (var bais = new ByteArrayInputStream(serialized);
                var in = new ObjectInputStream(bais)) {
            var obj = in.readObject();
            assertThat(obj).isInstanceOf(DummyResource.class);
            restored = (DummyResource) obj;
        }
        assertThat(restored).isNotSameAs(challenge);

        // Make sure the restored object is not attached to a login
        assertThrows(IllegalStateException.class, restored::getLogin);

        // Rebind to login
        restored.rebind(login);

        // Make sure the new login is set
        assertThat(restored.getLogin()).isEqualTo(login);
    }

    /**
     * Test if a rebind attempt fails.
     */
    @Test
    public void testRebind() {
        assertThrows(IllegalStateException.class, () -> {
            var login = TestUtils.login();
            var location = new URL("http://example.com/acme/resource");

            var resource = new DummyResource(login, location);
            assertThat(resource.getLogin()).isEqualTo(login);

            var login2 = TestUtils.login();
            resource.rebind(login2); // fails to rebind to another login
        });
    }

    /**
     * Minimum implementation of {@link AcmeResource}.
     */
    private static class DummyResource extends AcmeResource {
        @Serial
        private static final long serialVersionUID = 7188822681353082472L;
        public DummyResource(Login login, URL location) {
            super(login, location);
        }
    }

}
