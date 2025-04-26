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

import java.io.Serial;
import java.io.Serializable;
import java.net.URL;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * This is the root class of all ACME resources (like accounts, orders, certificates).
 * Every resource is identified by its location URL.
 * <p>
 * This class also takes care for proper serialization and de-serialization of the
 * resource. After de-serialization, the resource must be bound to a {@link Login} again,
 * using {@link #rebind(Login)}.
 */
public abstract class AcmeResource implements Serializable {
    @Serial
    private static final long serialVersionUID = -7930580802257379731L;

    private transient @Nullable Login login;
    private final URL location;

    /**
     * Create a new {@link AcmeResource}.
     *
     * @param login
     *            {@link Login} the resource is bound with
     * @param location
     *            Location {@link URL} of this resource
     */
    protected AcmeResource(Login login, URL location) {
        this.location = Objects.requireNonNull(location, "location");
        rebind(login);
    }

    /**
     * Gets the {@link Login} this resource is bound with.
     */
    protected Login getLogin() {
        if (login == null) {
            throw new IllegalStateException("Use rebind() for binding this object to a login.");
        }
        return login;
    }

    /**
     * Gets the {@link Session} this resource is bound with.
     */
    protected Session getSession() {
        return getLogin().getSession();
    }

    /**
     * Rebinds this resource to a {@link Login}.
     * <p>
     * Logins are not serialized, because they contain volatile session data and also a
     * private key. After de-serialization of an {@link AcmeResource}, use this method to
     * rebind it to a {@link Login}.
     *
     * @param login
     *            {@link Login} to bind this resource to
     */
    public void rebind(Login login) {
        if (this.login != null) {
            throw new IllegalStateException("Resource is already bound to a login");
        }
        this.login = Objects.requireNonNull(login, "login");
    }

    /**
     * Gets the resource's location.
     */
    public URL getLocation() {
        return location;
    }

    @Override
    protected final void finalize() {
        // CT_CONSTRUCTOR_THROW: Prevents finalizer attack
    }

}
