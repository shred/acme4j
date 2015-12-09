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
package org.shredzone.acme4j.connector;

/**
 * A session for tracking communication parameters.
 *
 * @author Richard "Shred" Körber
 */
public class Session {

    private byte[] nonce;

    /**
     * Gets the last nonce, or {@code null} if the session is new.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce received by the server.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

}
