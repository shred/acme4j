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
package org.shredzone.acme4j.util;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.shredzone.acme4j.util.TimestampParser.parse;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Test;

/**
 * Unit tests for {@link TimestampParser}.
 */
public class TimestampParserTest {

    /**
     * Test valid strings.
     */
    @Test
    public void testParser() {
        assertThat(parse("2015-12-27T22:58:35.006769519Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.00676951Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.0067695Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.006769Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.00676Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.0067Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.006Z"), isDate(2015, 12, 27, 22, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.01Z"), isDate(2015, 12, 27, 22, 58, 35, 10));
        assertThat(parse("2015-12-27T22:58:35.2Z"), isDate(2015, 12, 27, 22, 58, 35, 200));
        assertThat(parse("2015-12-27T22:58:35Z"), isDate(2015, 12, 27, 22, 58, 35));
        assertThat(parse("2015-12-27t22:58:35z"), isDate(2015, 12, 27, 22, 58, 35));

        assertThat(parse("2015-12-27T22:58:35.006769519+02:00"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.006+02:00"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35+02:00"), isDate(2015, 12, 27, 20, 58, 35));

        assertThat(parse("2015-12-27T21:58:35.006769519-02:00"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parse("2015-12-27T21:58:35.006-02:00"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parse("2015-12-27T21:58:35-02:00"), isDate(2015, 12, 27, 23, 58, 35));

        assertThat(parse("2015-12-27T22:58:35.006769519+0200"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35.006+0200"), isDate(2015, 12, 27, 20, 58, 35, 6));
        assertThat(parse("2015-12-27T22:58:35+0200"), isDate(2015, 12, 27, 20, 58, 35));

        assertThat(parse("2015-12-27T21:58:35.006769519-0200"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parse("2015-12-27T21:58:35.006-0200"), isDate(2015, 12, 27, 23, 58, 35, 6));
        assertThat(parse("2015-12-27T21:58:35-0200"), isDate(2015, 12, 27, 23, 58, 35));
    }

    /**
     * Test invalid strings.
     */
    @Test
    public void testInvalid() {
        try {
            parse("");
            fail("accepted empty string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parse("abc");
            fail("accepted nonsense string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parse("2015-12-27");
            fail("accepted year only string");
        } catch (IllegalArgumentException ex) {
            // expected
        }

        try {
            parse("2015-12-27T");
            fail("accepted year only string");
        } catch (IllegalArgumentException ex) {
            // expected
        }
    }

    /**
     * Test that constructor is private.
     */
    @Test
    public void testPrivateConstructor() throws Exception {
        Constructor<TimestampParser> constructor = TimestampParser.class.getDeclaredConstructor();
        assertThat(Modifier.isPrivate(constructor.getModifiers()), is(true));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    /**
     * Matches the given time.
     */
    private DateMatcher isDate(int year, int month, int dom, int hour, int minute, int second) {
        return isDate(year, month, dom, hour, minute, second, 0);
    }

    /**
     * Matches the given time and milliseconds.
     */
    private DateMatcher isDate(int year, int month, int dom, int hour, int minute, int second, int ms) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(year, month - 1, dom, hour, minute, second);
        cal.set(Calendar.MILLISECOND, ms);
        return new DateMatcher(cal);
    }

    /**
     * Date matcher that gives a readable output on mismatch.
     */
    private static class DateMatcher extends BaseMatcher<Date> {

        private final Calendar cal;
        private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH);

        public DateMatcher(Calendar cal) {
            this.cal = cal;
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        }

        @Override
        public boolean matches(Object item) {
            if (!(item instanceof Date)) {
                return false;
            }

            Date date = (Date) item;
            return date.equals(cal.getTime());
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(sdf.format(cal.getTime()));
        }

        @Override
        public void describeMismatch(Object item, Description description) {
            if (!(item instanceof Date)) {
                description.appendText("is not a Date");
                return;
            }

            Date date = (Date) item;
            description.appendText("was ").appendValue(sdf.format(date));
        }

    }

}
