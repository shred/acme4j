/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2026 Richard "Shred" Körber
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

import static java.util.Objects.requireNonNull;

import java.io.Serial;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.AcmeUtils;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge. It requires a specific DNS record for domain
 * validation. See the acme4j documentation for a detailed explanation.
 *
 * @draft This class is currently based on an RFC draft. It may be changed or removed
 * without notice to reflect future changes to the draft. SemVer rules do not apply here.
 * @since 5.0.0
 */
public class DnsPersist01Challenge extends Challenge {
    @Serial
    private static final long serialVersionUID = 7532514098897449519L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-persist-01";

    protected static final String KEY_ISSUER_DOMAIN_NAMES = "issuer-domain-names";
    protected static final String RECORD_NAME_PREFIX = "_validation-persist";
    protected static final String KEY_ACCOUNT_URI = "accounturi";

    private static final int ISSUER_SIZE_LIMIT = 10;        // according to the specs
    private static final int DOMAIN_LENGTH_LIMIT = 253;     // according to the specs

    private @Nullable List<String> issuerDomainNames;

    /**
     * Creates a new generic {@link DnsPersist01Challenge} object.
     *
     * @param login
     *         {@link Login} the resource is bound with
     * @param data
     *         {@link JSON} challenge data
     */
    public DnsPersist01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Returns the list of issuer-domain-names from the CA. The list is guaranteed to
     * have at least one element.
     */
    public List<String> getIssuerDomainNames() {
        if (issuerDomainNames == null) {
            var domainNames = getJSON().get(KEY_ISSUER_DOMAIN_NAMES).asArray().stream()
                    .map(JSON.Value::asString)
                    .map(AcmeUtils::toAce)
                    .toList();

            if (domainNames.isEmpty()) {
                // malform check is mandatory according to the specification
                throw new AcmeProtocolException("issuer-domain-names missing or empty");
            }

            if (domainNames.size() > ISSUER_SIZE_LIMIT) {
                // malform check is mandatory according to the specification
                throw new AcmeProtocolException("issuer-domain-names size limit exceeded: "
                        + domainNames.size() + " > " + ISSUER_SIZE_LIMIT);
            }

            if (domainNames.stream().anyMatch(it -> it.endsWith("."))) {
                throw new AcmeProtocolException("issuer-domain-names must not have trailing dots");
            }

            if (!domainNames.stream().allMatch(it -> it.length() <= DOMAIN_LENGTH_LIMIT)) {
                throw new AcmeProtocolException("issuer-domain-names content too long");
            }

            issuerDomainNames = domainNames;
        }
        return Collections.unmodifiableList(issuerDomainNames);
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param identifier
     *         Domain {@link Identifier} of the domain to be validated
     * @return Resource Record name (e.g. {@code _validation-persist.www.example.org.},
     * note the trailing full stop character).
     */
    public String getRRName(Identifier identifier) {
        return getRRName(identifier.getDomain());
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param domain
     *         Domain name to be validated
     * @return Resource Record name (e.g. {@code _validation-persist.www.example.org.},
     * note the trailing full stop character).
     */
    public String getRRName(String domain) {
        return RECORD_NAME_PREFIX + '.' + AcmeUtils.toAce(domain) + '.';
    }

    /**
     * Returns a builder for the RDATA value of the DNS TXT record.
     *
     * @return Builder for the RDATA
     */
    public Builder buildRData() {
        return new Builder(getLogin(), getIssuerDomainNames());
    }

    /**
     * Convenience call to get a standard RDATA without optional tags.
     *
     * @return RRDATA
     */
    public String getRData() {
        return buildRData().build();
    }

    /**
     * Returns the Account URI that is expected to request the validation.
     *
     * @since 5.1.0
     */
    public URL getAccountUrl() {
        return getJSON().get(KEY_ACCOUNT_URI).asURL();
    }

    @Override
    protected void invalidate() {
        super.invalidate();
        issuerDomainNames = null;
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

    @Override
    protected void setJSON(JSON json) {
        super.setJSON(json);
        // TODO: In a future release, KEY_ACCOUNT_URI is expected to be mandatory,
        //   and this check will always apply!
        if (getJSON().contains(KEY_ACCOUNT_URI)) {
            try {
                var expectedAccount = getJSON().get(KEY_ACCOUNT_URI).asURI();
                var actualAccount = getLogin().getAccount().getLocation().toURI();
                if (!actualAccount.equals(expectedAccount)) {
                    throw new AcmeProtocolException("challenge is intended for a different account: " + expectedAccount);
                }
            } catch (URISyntaxException ex) {
                throw new IllegalStateException("Account URL is not an URI?", ex);
            }
        }
    }

    /**
     * Builder for RDATA.
     * <p>
     * The following default values are assumed unless overridden by one of the builder
     * methods:
     * <ul>
     *     <li>The first issuer domain name from the list of issuer domain names is used</li>
     *     <li>No wildcard domain</li>
     *     <li>No persistence limit</li>
     *     <li>Generate quote-enclosed strings</li>
     * </ul>
     */
    public static class Builder {
        private final Login login;
        private final List<String> issuerDomainNames;
        private String issuer;
        private boolean wildcard = false;
        private boolean quotes = true;
        private @Nullable Instant persistUntil = null;

        private Builder(Login login, List<String> issuerDomainNames) {
            this.login = login;
            this.issuerDomainNames = issuerDomainNames;
            this.issuer = issuerDomainNames.get(0);
        }

        /**
         * Change the issuer domain name.
         *
         * @param issuer
         *         Issuer domain name, must be one of
         *         {@link DnsPersist01Challenge#getIssuerDomainNames()}.
         */
        public Builder issuerDomainName(String issuer) {
            requireNonNull(issuer, "issuer");
            if (!issuerDomainNames.contains(issuer)) {
                throw new IllegalArgumentException("Domain " + issuer + " is not in the list of issuer-domain-names");
            }
            this.issuer = issuer;
            return this;
        }

        /**
         * Request wildcard validation.
         */
        public Builder wildcard() {
            wildcard = true;
            return this;
        }

        /**
         * Instant until this RDATA is valid. The CA must not use this record after that.
         *
         * @param instant
         *         Persist until instant
         */
        public Builder persistUntil(Instant instant) {
            persistUntil = requireNonNull(instant, "instant");
            return this;
        }

        /**
         * Do not use quote-enclosed strings. Proper formatting of the resulting RDATA
         * must be done externally!
         */
        public Builder noQuotes() {
            quotes = false;
            return this;
        }

        /**
         * Build the RDATA string for the DNS TXT record.
         */
        public String build() {
            var parts = new ArrayList<String>();
            parts.add(issuer);
            parts.add("accounturi=" + login.getAccount().getLocation());

            if (wildcard) {
                parts.add("policy=wildcard");
            }

            if (persistUntil != null) {
                parts.add("persistUntil=" + persistUntil.getEpochSecond());
            }

            if (quotes) {
                // Quotes inside the parts should be escaped. However, we don't expect
                // that any part contains qoutes.
                return '"' + String.join(";\" \" ", parts) + '"';
            } else {
                return String.join("; ", parts);
            }
        }
    }

}
