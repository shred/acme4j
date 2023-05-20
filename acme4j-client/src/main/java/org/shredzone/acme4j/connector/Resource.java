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
 * Enumeration of standard resources, and their key name in the CA's directory.
 */
public enum Resource {

    NEW_NONCE("newNonce"),
    NEW_ACCOUNT("newAccount"),
    NEW_ORDER("newOrder"),
    NEW_AUTHZ("newAuthz"),
    REVOKE_CERT("revokeCert"),
    KEY_CHANGE("keyChange"),
    RENEWAL_INFO("renewalInfo");

    private final String path;

    Resource(String path) {
        this.path = path;
    }

    /**
     * Returns the key name in the directory.
     *
     * @return key name
     */
    public String path() {
        return path;
    }

}
