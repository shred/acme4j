/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
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

import java.security.KeyPair;

/**
 * Represents an account at the ACME server.
 * <p>
 * An account is identified by its {@link KeyPair}.
 *
 * @author Richard "Shred" Körber
 */
public class Account {

    private final KeyPair keyPair;

    /**
     * Creates a new {@link Account} instance.
     *
     * @param keyPair
     *            {@link KeyPair} that identifies the account.
     */
    public Account(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * The {@link KeyPair} that belongs to this account.
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

}
