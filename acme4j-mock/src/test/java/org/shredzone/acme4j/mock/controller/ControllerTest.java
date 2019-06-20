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
package org.shredzone.acme4j.mock.controller;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link Controller}.
 */
public class ControllerTest {

    /**
     * Make sure all default implementations throw a HTTP 405 exception.
     */
    @Test
    public void testDefaults() throws MalformedURLException {
        URL requestUrl = new URL("https://acme.test/test");
        PublicKey publicKey = KeyPairUtils.createKeyPair(1024).getPublic();
        JSON payload = JSON.empty();

        Controller controller = new Controller() {};

        try {
            controller.doSimpleRequest(requestUrl);
            fail("doSimpleRequest did not throw an error");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), is("HTTP 405: Method Not Allowed"));
        }

        try {
            controller.doPostAsGetRequest(requestUrl, publicKey);
            fail("doPostAsGetRequest did not throw an error");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), is("HTTP 405: Method Not Allowed"));
        }

        try {
            controller.doPostRequest(requestUrl, payload, publicKey);
            fail("doPostRequest did not throw an error");
        } catch (AcmeException ex) {
            assertThat(ex.getMessage(), is("HTTP 405: Method Not Allowed"));
        }
    }

}