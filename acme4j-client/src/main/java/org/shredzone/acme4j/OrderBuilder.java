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
import static java.util.stream.Collectors.toList;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder for a new {@link Order} object.
 */
@ParametersAreNonnullByDefault
public class OrderBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(OrderBuilder.class);

    private final Login login;

    private final Set<Identifier> identifierSet = new LinkedHashSet<>();
    private Instant notBefore;
    private Instant notAfter;
    private boolean recurrent;
    private Instant recurrentStart;
    private Instant recurrentEnd;
    private Duration recurrentValidity;

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
        return identifier(Identifier.dns(domain));
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
     * Adds an {@link Identifier} to the order.
     *
     * @param identifier
     *            {@link Identifier} to be added to the order.
     * @return itself
     * @since 2.3
     */
    public OrderBuilder identifier(Identifier identifier) {
        identifierSet.add(requireNonNull(identifier, "identifier"));
        return this;
    }

    /**
     * Adds a collection of {@link Identifier} to the order.
     *
     * @param identifiers
     *            Collection of {@link Identifier} to be added to the order.
     * @return itself
     * @since 2.3
     */
    public OrderBuilder identifiers(Collection<Identifier> identifiers) {
        requireNonNull(identifiers, "identifiers").forEach(this::identifier);
        return this;
    }

    /**
     * Sets a "not before" date in the certificate. May be ignored by the CA.
     *
     * @param notBefore "not before" date
     * @return itself
     */
    public OrderBuilder notBefore(Instant notBefore) {
        if (recurrent) {
            throw new IllegalArgumentException("cannot combine notBefore with recurrent");
        }
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
        if (recurrent) {
            throw new IllegalArgumentException("cannot combine notAfter with recurrent");
        }
        this.notAfter = requireNonNull(notAfter, "notAfter");
        return this;
    }

    /**
     * Enables short-term automatic renewal of the certificate. Must be supported by the
     * CA.
     * <p>
     * Recurrent renewals cannot be combined with {@link #notBefore(Instant)} or
     * {@link #notAfter(Instant)}.
     *
     * @return itself
     * @since 2.3
     */
    public OrderBuilder recurrent() {
        if (notBefore != null || notAfter != null) {
            throw new IllegalArgumentException("cannot combine notBefore/notAfter with recurrent");
        }
        this.recurrent = true;
        return this;
    }

    /**
     * Sets the earliest date of validity of the first issued certificate. If not set,
     * the start date is the earliest possible date.
     * <p>
     * Implies {@link #recurrent()}.
     *
     * @param start
     *            Start date of validity
     * @return itself
     * @since 2.3
     */
    public OrderBuilder recurrentStart(Instant start) {
        recurrent();
        this.recurrentStart = requireNonNull(start, "start");
        return this;
    }

    /**
     * Sets the latest date of validity of the last issued certificate. If not set, the
     * CA's default is used.
     * <p>
     * Implies {@link #recurrent()}.
     *
     * @param end
     *            End date of validity
     * @return itself
     * @see Metadata#getStarMaxRenewal()
     * @since 2.3
     */
    public OrderBuilder recurrentEnd(Instant end) {
        recurrent();
        this.recurrentEnd = requireNonNull(end, "end");
        return this;
    }

    /**
     * Sets the maximum validity period of each certificate. If not set, the CA's
     * default is used.
     * <p>
     * Implies {@link #recurrent()}.
     *
     * @param duration
     *            Duration of validity of each certificate
     * @return itself
     * @see Metadata#getStarMinCertValidity()
     * @since 2.3
     */
    public OrderBuilder recurrentCertificateValidity(Duration duration) {
        recurrent();
        this.recurrentValidity = requireNonNull(duration, "duration");
        return this;
    }

    /**
     * Sends a new order to the server, and returns an {@link Order} object.
     *
     * @return {@link Order} that was created
     */
    public Order create() throws AcmeException {
        if (identifierSet.isEmpty()) {
            throw new IllegalArgumentException("At least one identifer is required");
        }

        Session session = login.getSession();

        if (recurrent && !session.getMetadata().isStarEnabled()) {
            throw new AcmeException("CA does not support short-term automatic renewals");
        }

        LOG.debug("create");
        try (Connection conn = session.connect()) {
            JSONBuilder claims = new JSONBuilder();
            claims.array("identifiers", identifierSet.stream().map(Identifier::toMap).collect(toList()));

            if (notBefore != null) {
                claims.put("notBefore", notBefore);
            }
            if (notAfter != null) {
                claims.put("notAfter", notAfter);
            }

            if (recurrent) {
                claims.put("recurrent", true);
                if (recurrentStart != null) {
                    claims.put("recurrent-start-date", recurrentStart);
                }
                if (recurrentStart != null) {
                    claims.put("recurrent-end-date", recurrentEnd);
                }
                if (recurrentValidity != null) {
                    claims.put("recurrent-certificate-validity", recurrentValidity);
                }
            }

            conn.sendSignedRequest(session.resourceUrl(Resource.NEW_ORDER), claims, login);

            URL orderLocation = conn.getLocation();
            if (orderLocation == null) {
                throw new AcmeProtocolException("Server did not provide an order location");
            }

            Order order = new Order(login, orderLocation);
            JSON json = conn.readJsonResponse();
            if (json != null) {
                order.setJSON(json);
            }
            return order;
        }
    }

}
