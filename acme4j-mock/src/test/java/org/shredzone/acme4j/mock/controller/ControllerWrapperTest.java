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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * Unit tests for {@link ControllerWrapper}.
 */
public class ControllerWrapperTest {
    private final PublicKey publicKey = KeyPairUtils.createKeyPair(1024).getPublic();

    @Test
    public void testSimpleForwarding() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://acme.test/test");

        Controller controller = mock(Controller.class);

        ControllerWrapper<Controller> wrapper = new ControllerWrapper<Controller>(controller) {};
        wrapper.doSimpleRequest(requestUrl);

        verify(controller).doSimpleRequest(eq(requestUrl));
        verifyNoMoreInteractions(controller);
    }

    @Test
    public void testPostAsGetForwarding() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://acme.test/test");

        Controller controller = mock(Controller.class);

        ControllerWrapper<Controller> wrapper = new ControllerWrapper<Controller>(controller) {};
        wrapper.doPostAsGetRequest(requestUrl, publicKey);

        verify(controller).doPostAsGetRequest(eq(requestUrl), eq(publicKey));
        verifyNoMoreInteractions(controller);
    }

    @Test
    public void testPostForwarding() throws AcmeException, MalformedURLException {
        URL requestUrl = new URL("https://acme.test/test");
        JSON payload = JSON.empty();

        Controller controller = mock(Controller.class);

        ControllerWrapper<Controller> wrapper = new ControllerWrapper<Controller>(controller) {};
        wrapper.doPostRequest(requestUrl, payload, publicKey);

        verify(controller).doPostRequest(eq(requestUrl), eq(payload), eq(publicKey));
        verifyNoMoreInteractions(controller);
    }

}
