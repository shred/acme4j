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
 * Enumeration of resources.
 */
public enum Resource {

    NEW_NONCE("new-nonce"),
    NEW_ACCOUNT("new-account"),
    NEW_ORDER("new-order"),
    NEW_AUTHZ("new-authz"),
    REVOKE_CERT("revoke-cert"),
    KEY_CHANGE("key-change");

    private final String path;

    private Resource(String path) {
        this.path = path;
    }

    /**
     * Returns the resource path.
     *
     * @return resource path
     */
    public String path() {
        return path;
    }

}
