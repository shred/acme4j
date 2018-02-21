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
package org.shredzone.acme4j;

import static java.util.Objects.requireNonNull;
import static org.shredzone.acme4j.toolbox.AcmeUtils.toAce;

import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder for a new {@link Order} object.
 */
public class OrderBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(OrderBuilder.class);

    private final Login login;

    private final Set<String> domainSet = new LinkedHashSet<>();
    private Instant notBefore;
    private Instant notAfter;

    /**
     * Create a new {@link OrderBuilder}.
     *
     * @param login
     *            {@link Login} to bind with
     */
    protected OrderBuilder(Login login) {
        this.login = login;
    }

    /**
     * Adds a domain name to the order.
     *
     * @param domain
     *            Name of a domain to be ordered. May be a wildcard domain if supported by
     *            the CA. IDN names are accepted and will be ACE encoded automatically.
     * @return itself
     */
    public OrderBuilder domain(String domain) {
        domainSet.add(toAce(requireNonNull(domain, "domain")));
        return this;
    }

    /**
     * Adds domain names to the order.
     *
     * @param domains
     *            Collection of domain names to be ordered. May be wildcard domains if
     *            supported by the CA. IDN names are accepted and will be ACE encoded
     *            automatically.
     * @return itself
     */
    public OrderBuilder domains(String... domains) {
        for (String domain : requireNonNull(domains, "domains")) {
            domain(domain);
        }
        return this;
    }

    /**
     * Adds a collection of domain names to the order.
     *
     * @param domains
     *            Collection of domain names to be ordered. May be wildcard domains if
     *            supported by the CA. IDN names are accepted and will be ACE encoded
     *            automatically.
     * @return itself
     */
    public OrderBuilder domains(Collection<String> domains) {
        requireNonNull(domains, "domains").forEach(this::domain);
        return this;
    }

    /**
     * Sets a "not before" date in the certificate. May be ignored by the CA.
     *
     * @param notBefore "not before" date
     * @return itself
     */
    public OrderBuilder notBefore(Instant notBefore) {
        this.notBefore = requireNonNull(notBefore, "notBefore");
        return this;
    }

    /**
     * Sets a "not after" date in the certificate. May be ignored by the CA.
     *
     * @param notAfter "not after" date
     * @return itself
     */
    public OrderBuilder notAfter(Instant notAfter) {
        this.notAfter = requireNonNull(notAfter, "notAfter");
        return this;
    }

    /**
     * Sends a new order to the server, and returns an {@link Order} object.
     *
     * @return {@link Order} that was created
     */
    public Order create() throws AcmeException {
        if (domainSet.isEmpty()) {
            throw new IllegalArgumentException("At least one domain is required");
        }

        Session session = login.getSession();

        Object[] identifiers = new Object[domainSet.size()];
        Iterator<String> di = domainSet.iterator();
        for (int ix = 0; ix < identifiers.length; ix++) {
            identifiers[ix] = new JSONBuilder()
                            .put("type", "dns")
                            .put("value", di.next())
                            .toMap();
        }

        LOG.debug("create");
        try (Connection conn = session.provider().connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.array("identifiers", identifiers);

            if (notBefore != null) {
                claims.put("notBefore", notBefore);
            }
            if (notAfter != null) {
                claims.put("notAfter", notAfter);
            }

            conn.sendSignedRequest(session.resourceUrl(Resource.NEW_ORDER), claims, login);

            Order order = new Order(login, conn.getLocation());
            order.setJSON(conn.readJsonResponse());
            return order;
        }
    }

}
