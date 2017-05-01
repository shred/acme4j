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
package org.shredzone.acme4j.provider.pebble;

import org.slf4j.LoggerFactory;

/**
 * Check if Pebble workarounds or strict ACME specifications are to be used.
 * <p>
 * To enable the Pebble workarounds, pass {@code -Dpebble=true} to the JVM.
 * <p>
 * Do not use this class. It will be removed.
 */
public final class Pebble {

    private static final boolean PEBBLE = Boolean.getBoolean("pebble");

    static {
        if (PEBBLE) {
            LoggerFactory.getLogger(Pebble.class).warn("Pebble workarounds enabled!");
        }
    }

    private Pebble() {
        // utility class without constructor
    }

    /**
     * Returns {@code true} to enable Pebble workarounds, {@code false} for strict
     * ACME specifications.
     */
    public static boolean workaround() {
        return PEBBLE;
    }

}
