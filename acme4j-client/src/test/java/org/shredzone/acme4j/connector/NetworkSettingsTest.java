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
package org.shredzone.acme4j.connector;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Duration;

import org.junit.Test;

/**
 * Unit tests for {@link NetworkSettings}.
 */
public class NetworkSettingsTest {

    /**
     * Test getters and setters.
     */
    @Test
    public void testGettersAndSetters() {
        NetworkSettings settings = new NetworkSettings();

        assertThat(settings.getProxy(), is(Proxy.NO_PROXY));
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("10.0.0.1", 8080));
        settings.setProxy(proxy);
        assertThat(settings.getProxy(), is(proxy));
        settings.setProxy(null);
        assertThat(settings.getProxy(), is(Proxy.NO_PROXY));

        assertThat(settings.getTimeout(), is(Duration.ofSeconds(10)));
        settings.setTimeout(Duration.ofMillis(5120));
        assertThat(settings.getTimeout(), is(Duration.ofMillis(5120)));
    }

    @Test
    public void testInvalidTimeouts() {
        NetworkSettings settings = new NetworkSettings();

        try {
            settings.setTimeout(null);
            fail("timeout accepted null");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            settings.setTimeout(Duration.ZERO);
            fail("timeout accepted zero duration");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            settings.setTimeout(Duration.ofSeconds(20).negated());
            fail("timeout accepted negative duration");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            settings.setTimeout(Duration.ofMillis(Integer.MAX_VALUE + 1L));
            fail("timeout accepted out of range value");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

}
