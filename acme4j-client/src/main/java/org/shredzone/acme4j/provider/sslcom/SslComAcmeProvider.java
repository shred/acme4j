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
package org.shredzone.acme4j.provider.sslcom;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;

/**
 * An {@link AcmeProvider} for <em>SSL.com</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://ssl.com"} for the production server,
 * and {@code "acme://acme-try.ssl.com"} for a testing server.
 * <p>
 * If you want to use <em>SSL.com</em>, always prefer to use this provider.
 *
 * @see <a href="https://ssl.com/">SSL.com</a>
 */
public class SslComAcmeProvider extends AbstractAcmeProvider {

    private static final String V02_DIRECTORY_URL = "https://acme.ssl.com/sslcom-dv-ecc";
    private static final String STAGING_DIRECTORY_URL = "https://acme-try.ssl.com/sslcom-dv-ecc";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "ssl.com".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        var path = serverUri.getPath();
        String directoryUrl;
        if (path == null || "".equals(path) || "/".equals(path) || "/v02".equals(path)) {
            directoryUrl = V02_DIRECTORY_URL;
        } else if ("/staging".equals(path)) {
            directoryUrl = STAGING_DIRECTORY_URL;
        } else {
            throw new IllegalArgumentException("Unknown URI " + serverUri);
        }

        try {
            return new URL(directoryUrl);
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException(directoryUrl, ex);
        }
    }

}
