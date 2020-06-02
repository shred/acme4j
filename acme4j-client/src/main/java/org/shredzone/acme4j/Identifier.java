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

import static java.util.Objects.requireNonNull;
import static org.shredzone.acme4j.toolbox.AcmeUtils.toAce;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Represents an identifier.
 * <p>
 * The ACME protocol only defines the DNS identifier, which identifies a domain name.
 * acme4j also supports IP identifiers.
 * <p>
 * CAs may define further, proprietary identifier types.
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

    private static final String KEY_TYPE = "type";
    private static final String KEY_VALUE = "value";

    private final String type;
    private final String value;

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
        this.type = requireNonNull(type, KEY_TYPE);
        this.value = requireNonNull(value, KEY_VALUE);
    }

    /**
     * Creates a new {@link Identifier} from the given {@link JSON} structure.
     *
     * @param json
     *            {@link JSON} containing the identifier data
     */
    public Identifier(JSON json) {
        this(json.get(KEY_TYPE).asString(), json.get(KEY_VALUE).asString());
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
     * Returns the identifier type.
     */
    public String getType() {
        return type;
    }

    /**
     * Returns the identifier value.
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns the domain name if this is a DNS identifier.
     *
     * @return Domain name. Unicode domains are ASCII encoded.
     * @throws AcmeProtocolException
     *             if this is not a DNS identifier.
     */
    public String getDomain() {
        if (!TYPE_DNS.equals(type)) {
            throw new AcmeProtocolException("expected 'dns' identifier, but found '" + type + "'");
        }
        return value;
    }

    /**
     * Returns the IP address if this is an IP identifier.
     *
     * @return {@link InetAddress}
     * @throws AcmeProtocolException
     *             if this is not a DNS identifier.
     */
    public InetAddress getIP() {
        if (!TYPE_IP.equals(type)) {
            throw new AcmeProtocolException("expected 'ip' identifier, but found '" + type + "'");
        }
        try {
            return InetAddress.getByName(value);
        } catch (UnknownHostException ex) {
            throw new AcmeProtocolException("bad ip identifier value", ex);
        }
    }

    /**
     * Returns the identifier as JSON map.
     */
    public Map<String, Object> toMap() {
        return new JSONBuilder().put(KEY_TYPE, type).put(KEY_VALUE, value).toMap();
    }

    @Override
    public String toString() {
        return type + "=" + value;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Identifier)) {
            return false;
        }

        Identifier i = (Identifier) obj;
        return type.equals(i.type) && value.equals(i.value);
    }

    @Override
    public int hashCode() {
        return type.hashCode() ^ value.hashCode();
    }

}
