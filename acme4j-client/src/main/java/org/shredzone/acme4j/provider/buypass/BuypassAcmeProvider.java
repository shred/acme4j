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
package org.shredzone.acme4j.provider.buypass;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;

/**
 * An {@link AcmeProvider} for the <em>Buypass</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://buypass.com"} for the production server,
 * and {@code "acme://buypass.com/staging"} for the staging server.
 *
 * @see <a href="https://www.buypass.com/products/tls-ssl-certificates/go-ssl">https://www.buypass.com/products/tls-ssl-certificates/go-ssl</a>
 * @since 3.5.0
 */
public class BuypassAcmeProvider extends AbstractAcmeProvider {

    private static final String PRODUCTION_DIRECTORY_URL = "https://api.buypass.com/acme/directory";
    private static final String STAGING_DIRECTORY_URL = "https://api.test4.buypass.no/acme/directory";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "buypass.com".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        var path = serverUri.getPath();
        String directoryUrl;
        if (path == null || path.isEmpty() || "/".equals(path)) {
            directoryUrl = PRODUCTION_DIRECTORY_URL;
        } else if ("/staging".equals(path)) {
            directoryUrl = STAGING_DIRECTORY_URL;
        } else {
            throw new IllegalArgumentException("Unknown URI " + serverUri);
        }

        try {
            return URI.create(directoryUrl).toURL();
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException(directoryUrl, ex);
        }
    }

}
