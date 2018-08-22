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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

import org.junit.Test;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSONBuilder;

/**
 * Unit tests for {@link Identifier}.
 */
public class IdentifierTest {

    @Test
    public void testConstants() {
        assertThat(Identifier.TYPE_DNS, is("dns"));
        assertThat(Identifier.TYPE_IP, is("ip"));
    }

    @Test
    public void testGetters() {
        Identifier id1 = new Identifier("foo", "123.456");
        assertThat(id1.getType(), is("foo"));
        assertThat(id1.getValue(), is("123.456"));
        assertThat(id1.toString(), is("foo=123.456"));
        Map<String, Object> map1 = id1.toMap();
        assertThat(map1.size(), is(2));
        assertThat(map1.get("type"), is("foo"));
        assertThat(map1.get("value"), is("123.456"));

        JSONBuilder jb = new JSONBuilder();
        jb.put("type", "bar");
        jb.put("value", "654.321");
        Identifier id2 = new Identifier(jb.toJSON());
        assertThat(id2.getType(), is("bar"));
        assertThat(id2.getValue(), is("654.321"));
        assertThat(id2.toString(), is("bar=654.321"));
        Map<String, Object> map2 = id2.toMap();
        assertThat(map2.size(), is(2));
        assertThat(map2.get("type"), is("bar"));
        assertThat(map2.get("value"), is("654.321"));
    }

    @Test
    public void testDns() {
        Identifier id1 = Identifier.dns("example.com");
        assertThat(id1.getType(), is(Identifier.TYPE_DNS));
        assertThat(id1.getValue(), is("example.com"));
        assertThat(id1.getDomain(), is("example.com"));

        Identifier id2 = Identifier.dns("ëxämþlë.com");
        assertThat(id2.getType(), is(Identifier.TYPE_DNS));
        assertThat(id2.getValue(), is("xn--xml-qla7ae5k.com"));
        assertThat(id2.getDomain(), is("xn--xml-qla7ae5k.com"));
    }

    @Test(expected = AcmeProtocolException.class)
    public void testNoDns() {
        new Identifier("foo", "example.com").getDomain();
    }

    @Test
    public void testIp() throws UnknownHostException {
        Identifier id1 = Identifier.ip(InetAddress.getByName("192.168.1.2"));
        assertThat(id1.getType(), is(Identifier.TYPE_IP));
        assertThat(id1.getValue(), is("192.168.1.2"));
        assertThat(id1.getIP().getHostAddress(), is("192.168.1.2"));

        Identifier id2 = Identifier.ip(InetAddress.getByName("2001:db8:85a3::8a2e:370:7334"));
        assertThat(id2.getType(), is(Identifier.TYPE_IP));
        assertThat(id2.getValue(), is("2001:db8:85a3:0:0:8a2e:370:7334"));
        assertThat(id2.getIP().getHostAddress(), is("2001:db8:85a3:0:0:8a2e:370:7334"));
    }

    @Test(expected = AcmeProtocolException.class)
    public void testNoIp() {
        new Identifier("foo", "example.com").getIP();
    }

    @Test
    public void testEquals() {
        Identifier idRef = new Identifier("foo", "123.456");

        Identifier id1 = new Identifier("foo", "123.456");
        assertThat(idRef.equals(id1), is(true));

        Identifier id2 = new Identifier("bar", "654.321");
        assertThat(idRef.equals(id2), is(false));

        Identifier id3 = new Identifier("foo", "555.666");
        assertThat(idRef.equals(id3), is(false));

        Identifier id4 = new Identifier("sna", "123.456");
        assertThat(idRef.equals(id4), is(false));

        assertThat(idRef.equals(new Object()), is(false));
        assertThat(idRef.equals(null), is(false));
    }

    @Test
    public void testNull() {
        try {
            new Identifier(null, "123.456");
            fail("accepted null");
        } catch (NullPointerException ex) {
            // expected
        }

        try {
            new Identifier("foo", null);
            fail("accepted null");
        } catch (NullPointerException ex) {
            // expected
        }
    }

}
