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

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a timestamp as defined in RFC 3339.
 *
 * @see <a href="https://www.ietf.org/rfc/rfc3339.txt">RFC 3339</a>
 * @author Richard "Shred" Körber
 */
public class TimestampParser {

    private static final Pattern DATE_PATTERN = Pattern.compile(
                  "^(\\d{4})-(\\d{2})-(\\d{2})T"
                + "(\\d{2}):(\\d{2}):(\\d{2})"
                + "(?:\\.(\\d{1,3})\\d*)?"
                + "(Z|[+-]\\d{2}:?\\d{2})$", Pattern.CASE_INSENSITIVE);

    private static final Pattern TZ_PATTERN = Pattern.compile(
                  "([+-])(\\d{2}):?(\\d{2})$");

    /**
     * Parses a RFC 3339 formatted date.
     *
     * @param str
     *            Date string
     * @return {@link Date} that was parsed
     * @throws IllegalArgumentException
     *             if the date string was not RFC 3339 formatted
     */
    public static Date parse(String str) {
        Matcher m = DATE_PATTERN.matcher(str);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal date: " + str);
        }

        int year = Integer.parseInt(m.group(1));
        int month = Integer.parseInt(m.group(2));
        int dom = Integer.parseInt(m.group(3));
        int hour = Integer.parseInt(m.group(4));
        int minute = Integer.parseInt(m.group(5));
        int second = Integer.parseInt(m.group(6));

        String msStr = m.group(7);
        if (msStr == null) {
            msStr = "000";
        } else {
            while (msStr.length() < 3) {
                msStr += '0';
            }
        }
        int ms = Integer.parseInt(msStr);

        String tz = m.group(8);
        if ("Z".equalsIgnoreCase(tz)) {
            tz = "GMT";
        } else {
            tz = TZ_PATTERN.matcher(tz).replaceAll("GMT$1$2:$3");
        }

        Calendar cal = GregorianCalendar.getInstance(TimeZone.getTimeZone(tz));
        cal.clear();
        cal.set(year, month - 1, dom, hour, minute, second);
        cal.set(Calendar.MILLISECOND, ms);
        return cal.getTime();
    }

}
