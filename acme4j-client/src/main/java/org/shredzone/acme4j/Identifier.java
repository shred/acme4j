/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
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

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;
import static org.shredzone.acme4j.toolbox.AcmeUtils.toAce;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.TreeMap;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Represents an identifier.
 * <p>
 * The ACME protocol only defines the DNS identifier, which identifies a domain name.
 * acme4j also supports IP identifiers.
 * <p>
 * CAs, and other acme4j modules, may define further, proprietary identifier types.
 *
 * @since 2.3
 */
public class Identifier implements Serializable {
    private static final long serialVersionUID = -7777851842076362412L;

    /**
     * Type constant for DNS identifiers.
     */
    public static final String TYPE_DNS = "dns";

    /**
     * Type constant for IP identifiers.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8738">RFC 8738</a>
     */
    public static final String TYPE_IP = "ip";

    static final String KEY_TYPE = "type";
    static final String KEY_VALUE = "value";
    static final String KEY_ANCESTOR_DOMAIN = "ancestorDomain";
    static final String KEY_SUBDOMAIN_AUTH_ALLOWED = "subdomainAuthAllowed";

    private final Map<String, Object> content = new TreeMap<>();

    /**
     * Creates a new {@link Identifier}.
     * <p>
     * This is a generic constructor for identifiers. Refer to the documentation of your
     * CA to find out about the accepted identifier types and values.
     * <p>
     * Note that for DNS identifiers, no ASCII encoding of unicode domain takes place
     * here. Use {@link #dns(String)} instead.
     *
     * @param type
     *            Identifier type
     * @param value
     *            Identifier value
     */
    public Identifier(String type, String value) {
        content.put(KEY_TYPE, requireNonNull(type, KEY_TYPE));
        content.put(KEY_VALUE, requireNonNull(value, KEY_VALUE));
    }

    /**
     * Creates a new {@link Identifier} from the given {@link JSON} structure.
     *
     * @param json
     *            {@link JSON} containing the identifier data
     */
    public Identifier(JSON json) {
        if (!json.contains(KEY_TYPE)) {
            throw new AcmeProtocolException("Required key " + KEY_TYPE + " is missing");
        }
        if (!json.contains(KEY_VALUE)) {
            throw new AcmeProtocolException("Required key " + KEY_VALUE + " is missing");
        }
        content.putAll(json.toMap());
    }

    /**
     * Makes a copy of the given Identifier.
     */
    private Identifier(Identifier identifier) {
        content.putAll(identifier.content);
    }

    /**
     * Creates a new DNS identifier for the given domain name.
     *
     * @param domain
     *            Domain name. Unicode domains are automatically ASCII encoded.
     * @return New {@link Identifier}
     */
    public static Identifier dns(String domain) {
        return new Identifier(TYPE_DNS, toAce(domain));
    }

    /**
     * Creates a new IP identifier for the given {@link InetAddress}.
     *
     * @param ip
     *            {@link InetAddress}
     * @return New {@link Identifier}
     */
    public static Identifier ip(InetAddress ip) {
        return new Identifier(TYPE_IP, ip.getHostAddress());
    }

    /**
     * Creates a new IP identifier for the given {@link InetAddress}.
     *
     * @param ip
     *            IP address as {@link String}
     * @return New {@link Identifier}
     * @since 2.7
     */
    public static Identifier ip(String ip) {
        try {
            return ip(InetAddress.getByName(ip));
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Bad IP: " + ip, ex);
        }
    }

    /**
     * Sets an ancestor domain, as required in RFC-9444.
     *
     * @param domain
     *         The ancestor domain to be set. Unicode domains are automatically ASCII
     *         encoded.
     * @return An {@link Identifier} that contains the ancestor domain.
     * @since 3.3.0
     */
    public Identifier withAncestorDomain(String domain) {
        expectType(TYPE_DNS);

        var result = new Identifier(this);
        result.content.put(KEY_ANCESTOR_DOMAIN, toAce(domain));
        return result;
    }

    /**
     * Gives the permission to authorize subdomains of this domain, as required in
     * RFC-9444.
     *
     * @return An {@link Identifier} that allows subdomain auths.
     * @since 3.3.0
     */
    public Identifier allowSubdomainAuth() {
        expectType(TYPE_DNS);

        var result = new Identifier(this);
        result.content.put(KEY_SUBDOMAIN_AUTH_ALLOWED, true);
        return result;
    }

    /**
     * Returns the identifier type.
     */
    public String getType() {
        return content.get(KEY_TYPE).toString();
    }

    /**
     * Returns the identifier value.
     */
    public String getValue() {
        return content.get(KEY_VALUE).toString();
    }

    /**
     * Returns the domain name if this is a DNS identifier.
     *
     * @return Domain name. Unicode domains are ASCII encoded.
     * @throws AcmeProtocolException
     *             if this is not a DNS identifier.
     */
    public String getDomain() {
        expectType(TYPE_DNS);
        return getValue();
    }

    /**
     * Returns the IP address if this is an IP identifier.
     *
     * @return {@link InetAddress}
     * @throws AcmeProtocolException
     *             if this is not a DNS identifier.
     */
    public InetAddress getIP() {
        expectType(TYPE_IP);
        try {
            return InetAddress.getByName(getValue());
        } catch (UnknownHostException ex) {
            throw new AcmeProtocolException("bad ip identifier value", ex);
        }
    }

    /**
     * Returns the identifier as JSON map.
     */
    public Map<String, Object> toMap() {
        return unmodifiableMap(content);
    }

    /**
     * Makes sure this identifier is of the given type.
     *
     * @param type
     *         Expected type
     * @throws AcmeProtocolException
     *         if this identifier is of a different type
     */
    private void expectType(String type) {
        if (!type.equals(getType())) {
            throw new AcmeProtocolException("expected '" + type + "' identifier, but found '" + getType() + "'");
        }
    }

    @Override
    public String toString() {
        if (content.size() == 2) {
            return getType() + '=' + getValue();
        }
        return content.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Identifier)) {
            return false;
        }

        var i = (Identifier) obj;
        return content.equals(i.content);
    }

    @Override
    public int hashCode() {
        return content.hashCode();
    }

    @Override
    protected final void finalize() {
        // CT_CONSTRUCTOR_THROW: Prevents finalizer attack
    }

}
