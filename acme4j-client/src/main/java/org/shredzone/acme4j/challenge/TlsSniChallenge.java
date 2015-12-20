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
package org.shredzone.acme4j.challenge;

/**
 * Implements the {@code tls-sni-01} challenge.
 * <p>
 * <em>TODO: Currently this challenge is not implemented.</em>
 *
 * @author Richard "Shred" Körber
 */
public class TlsSniChallenge extends GenericChallenge {

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "tls-sni-01";

    public String getToken() {
        return get(KEY_TOKEN);
    }

    public void setToken(String token) {
        put(KEY_TOKEN, token);
    }

    public int getN() {
        return get("n");
    }

    public void setN(int n) {
        put("n", n);
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
