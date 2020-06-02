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

import java.net.Proxy;
import java.time.Duration;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Contains network settings to be used for network connections.
 *
 * @since 2.8
 */
public class NetworkSettings {

    private Proxy proxy = Proxy.NO_PROXY;
    private Duration timeout = Duration.ofSeconds(10);

    /**
     * Gets the {@link Proxy} to be used for connections.
     */
    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Sets a {@link Proxy} that is to be used for all connections. If {@code null},
     * {@link Proxy#NO_PROXY} is used, which is also the default.
     */
    public void setProxy(@Nullable Proxy proxy) {
        this.proxy = proxy != null ? proxy : Proxy.NO_PROXY;
    }

    /**
     * Gets the current network timeout.
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Sets the network timeout to be used for connections. Defaults to 10 seconds.
     *
     * @param timeout
     *         Network timeout {@link Duration}
     */
    public void setTimeout(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("Timeout must be positive");
        }
        if (timeout.toMillis() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Timeout is out of range");
        }

        this.timeout = timeout;
    }

}
