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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit tests for {@link DomainUtils}.
 */
public class DomainUtilsTest {

    /**
     * Test ACE conversion.
     */
    @Test
    public void testToAce() {
        // Test ASCII domains in different notations
        assertThat(DomainUtils.toAce("example.com"), is("example.com"));
        assertThat(DomainUtils.toAce("   example.com  "), is("example.com"));
        assertThat(DomainUtils.toAce("ExAmPlE.CoM"), is("example.com"));
        assertThat(DomainUtils.toAce("foo.example.com"), is("foo.example.com"));
        assertThat(DomainUtils.toAce("bar.foo.example.com"), is("bar.foo.example.com"));

        // Test IDN domains
        assertThat(DomainUtils.toAce("ExÄmþle.¢öM"), is("xn--exmle-hra7p.xn--m-7ba6w"));

        // Test alternate separators
        assertThat(DomainUtils.toAce("example\u3002com"), is("example.com"));
        assertThat(DomainUtils.toAce("example\uff0ecom"), is("example.com"));
        assertThat(DomainUtils.toAce("example\uff61com"), is("example.com"));

        // Test ACE encoded domains, they must not change
        assertThat(DomainUtils.toAce("xn--exmle-hra7p.xn--m-7ba6w"),
                                  is("xn--exmle-hra7p.xn--m-7ba6w"));

        // Test null
        assertThat(DomainUtils.toAce(null), is(nullValue()));
    }

}
