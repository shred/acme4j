/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2024 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider.zerossl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;

/**
 * An {@link AcmeProvider} for <em>ZeroSSL</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://zerossl.com"} for the production server.
 *
 * @see <a href="https://zerossl.com/">ZeroSSL</a>
 * @since 3.2.0
 */
public class ZeroSSLAcmeProvider extends AbstractAcmeProvider {

    private static final String V02_DIRECTORY_URL = "https://acme.zerossl.com/v2/DV90";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "zerossl.com".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        var path = serverUri.getPath();
        String directoryUrl;
        if (path == null || path.isEmpty() || "/".equals(path)) {
            directoryUrl = V02_DIRECTORY_URL;
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
