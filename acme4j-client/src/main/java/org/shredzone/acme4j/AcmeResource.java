/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
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

import java.io.Serializable;
import java.net.URL;
import java.util.Objects;

/**
 * A generic ACME resource.
 */
public abstract class AcmeResource implements Serializable {
    private static final long serialVersionUID = -7930580802257379731L;

    private transient Session session;
    private URL location;

    /**
     * Create a new {@link AcmeResource}.
     *
     * @param session
     *            {@link Session} the resource is bound with
     */
    protected AcmeResource(Session session) {
        rebind(session);
    }

    /**
     * Gets the {@link Session} this resource is bound with.
     */
    protected Session getSession() {
        if (session == null) {
            throw new IllegalStateException("Use Acme.reconnect() for reconnecting this object to a session.");
        }

        return session;
    }

    /**
     * Sets a new {@link Session}.
     */
    protected void setSession(Session session) {
        this.session = Objects.requireNonNull(session, "session");
    }

    /**
     * Sets the resource's location.
     */
    protected void setLocation(URL location) {
        this.location = Objects.requireNonNull(location, "location");
    }

    /**
     * Rebinds this resource to a {@link Session}.
     * <p>
     * Sessions are not serialized, because they contain volatile session data and also a
     * private key. After de-serialization of an {@link AcmeResource}, use this method to
     * rebind it to a {@link Session}.
     *
     * @param session
     *            {@link Session} to bind this resource to
     */
    public void rebind(Session session) {
        if (this.session != null) {
            throw new IllegalStateException("Resource is already bound to a session");
        }
        setSession(session);
    }

    /**
     * Gets the resource's location.
     */
    public URL getLocation() {
        return location;
    }

}
