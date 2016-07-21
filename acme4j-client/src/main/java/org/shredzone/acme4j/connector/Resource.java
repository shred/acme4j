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

    NEW_REG("new-reg"),
    NEW_AUTHZ("new-authz"),
    NEW_CERT("new-cert"),
    REVOKE_CERT("revoke-cert");

    /**
     * Parses the string and returns a matching {@link Resource} instance.
     *
     * @param str
     *            String to parse
     * @return {@link Resource} instance, or {@code null} if the resource is unknown
     */
    public static Resource parse(String str) {
        for (Resource r : values()) {
            if (r.path().equals(str)) {
                return r;
            }
        }

        return null;
    }

    private final String path;

    private Resource(String path) {
        this.path = path;
    }

    /**
     * Returns the resource path.
     */
    public String path() {
        return path;
    }

}
