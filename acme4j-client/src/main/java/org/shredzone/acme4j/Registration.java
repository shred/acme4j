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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a registration at the ACME server.
 *
 * @author Richard "Shred" Körber
 */
public class Registration {

    private List<URI> contacts = new ArrayList<>();
    private URI agreement;
    private URI location;

    /**
     * Create an empty {@link Registration}.
     */
    public Registration() {
        // default constructor
    }

    /**
     * Create a {@link Registration} for the given location URI.
     */
    public Registration(URI location) {
        this.location = location;
    }

    /**
     * Returns the URI of the agreement document the user is required to accept.
     */
    public URI getAgreement() {
        return agreement;
    }

    /**
     * Sets the URI of the agreement document the user is required to accept.
     */
    public void setAgreement(URI agreement) {
        this.agreement = agreement;
    }

    /**
     * List of contact addresses (emails, phone numbers etc).
     */
    public List<URI> getContacts() {
        return contacts;
    }

    /**
     * Add a contact URI to the list of contacts.
     *
     * @param contact
     *            Contact URI
     */
    public void addContact(URI contact) {
        getContacts().add(contact);
    }

    /**
     * Add a contact address to the list of contacts.
     * <p>
     * This is a convenience call for {@link #addContact(URI)}.
     *
     * @param contact
     *            Contact URI as string
     * @throws IllegalArgumentException
     *             if there is a syntax error in the URI string
     */
    public void addContact(String contact) {
        try {
            addContact(new URI(contact));
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid contact URI", ex);
        }
    }

    /**
     * Location URI of the registration at the server. Returned from the server after
     * successfully creating or updating a registration.
     */
    public URI getLocation() {
        return location;
    }

    /**
     * Location URI of the registration at the server. Must be set when updating the
     * registration.
     */
    public void setLocation(URI location) {
        this.location = location;
    }

}
