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
package org.shredzone.acme4j.it;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;

import org.junit.Ignore;
import org.junit.Test;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;

/**
 * Registration related integration tests.
 */
public class RegistrationIT extends AbstractPebbleIT {

    @Test
    public void testCreate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        // Register a new user
        RegistrationBuilder rb = new RegistrationBuilder();
        rb.addContact("mailto:acme@example.com");
        rb.agreeToTermsOfService();

        Registration reg = rb.create(session);
        URL location = reg.getLocation();
        assertIsPebbleUrl(location);
        assertThat(session.getKeyIdentifier(), is(location.toString()));

        // TODO: Not yet supported by Pebble
        /*
        // Check registered data
        assertThat(reg.getContacts(), contains(URI.create("mailto:acme@example.com")));
        assertThat(reg.getStatus(), is(Status.GOOD));
        assertThat(reg.getTermsOfServiceAgreed(), is(true));
        */

        // TODO: Not yet supported by Pebble
        /*
        // Bind another Registration object
        Session session2 = new Session(pebbleURI(), keyPair);
        Registration reg2 = Registration.bind(session2, location);
        assertThat(reg2.getLocation(), is(location));
        assertThat(reg2.getContacts(), contains(URI.create("mailto:acme@example.com")));
        assertThat(reg2.getStatus(), is(Status.GOOD));
        assertThat(reg2.getTermsOfServiceAgreed(), is(true));
        */
    }

    @Test
    @Ignore // TODO: Not yet supported by Pebble
    public void testModify() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        RegistrationBuilder rb = new RegistrationBuilder();
        rb.addContact("mailto:acme@example.com");
        rb.agreeToTermsOfService();

        Registration reg = rb.create(session);
        URL location = reg.getLocation();
        assertIsPebbleUrl(location);

        reg.modify().addContact("mailto:acme2@example.com").commit();

        assertThat(reg.getContacts(), contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com")));

        // Still the same after updating
        reg.update();
        assertThat(reg.getContacts(), contains(
                        URI.create("mailto:acme@example.com"),
                        URI.create("mailto:acme2@example.com")));
    }

    @Test
    @Ignore // TODO: Not yet supported by Pebble
    public void testKeyChange() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Registration reg = new RegistrationBuilder().agreeToTermsOfService().create(session);
        URL location = reg.getLocation();

        KeyPair newKeyPair = createKeyPair();
        reg.changeKey(newKeyPair);

        try {
            Session sessionOldKey = new Session(pebbleURI(), keyPair);
            Registration oldRegistration = Registration.bind(sessionOldKey, location);
            oldRegistration.update();
        } catch (AcmeUnauthorizedException ex) {
            // Expected
        }

        Session sessionNewKey = new Session(pebbleURI(), newKeyPair);
        Registration newRegistration = Registration.bind(sessionNewKey, location);
        assertThat(newRegistration.getStatus(), is(Status.GOOD));
    }

    @Test
    @Ignore // TODO: Not yet supported by Pebble
    public void testDeactivate() throws AcmeException {
        KeyPair keyPair = createKeyPair();
        Session session = new Session(pebbleURI(), keyPair);

        Registration reg = new RegistrationBuilder().agreeToTermsOfService().create(session);
        URL location = reg.getLocation();

        reg.deactivate();

        Session session2 = new Session(pebbleURI(), keyPair);
        Registration reg2 = Registration.bind(session2, location);
        assertThat(reg2.getLocation(), is(location));
        assertThat(reg2.getStatus(), is(Status.DEACTIVATED));
    }

}
