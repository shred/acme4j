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
package org.shredzone.acme4j.provider.sslcom;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Map;

import org.shredzone.acme4j.ISession;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * An {@link AcmeProvider} for <em>SSL.com</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://ssl.com"} for the production server,
 * and {@code "acme://acme-try.ssl.com"} for a testing server.
 * <p>
 * If you want to use <em>SSL.com</em>, always prefer to use this provider.
 *
 * @see <a href="https://ssl.com/">SSL.com</a>
 * @since 3.2.0
 */
public class SslComAcmeProvider extends AbstractAcmeProvider {

    private static final String PRODUCTION_ECC_DIRECTORY_URL = "https://acme.ssl.com/sslcom-dv-ecc";
    private static final String PRODUCTION_RSA_DIRECTORY_URL = "https://acme.ssl.com/sslcom-dv-rsa";
    private static final String STAGING_ECC_DIRECTORY_URL = "https://acme-try.ssl.com/sslcom-dv-ecc";
    private static final String STAGING_RSA_DIRECTORY_URL = "https://acme-try.ssl.com/sslcom-dv-rsa";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "ssl.com".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        var path = serverUri.getPath();
        String directoryUrl;
        if (path == null || path.isEmpty() || "/".equals(path) || "/ecc".equals(path)) {
            directoryUrl = PRODUCTION_ECC_DIRECTORY_URL;
        } else if ("/rsa".equals(path)) {
            directoryUrl = PRODUCTION_RSA_DIRECTORY_URL;
        } else if ("/staging".equals(path) || "/staging/ecc".equals(path)) {
            directoryUrl = STAGING_ECC_DIRECTORY_URL;
        } else if ("/staging/rsa".equals(path)) {
            directoryUrl = STAGING_RSA_DIRECTORY_URL;
        } else {
            throw new IllegalArgumentException("Unknown URI " + serverUri);
        }

        try {
            return URI.create(directoryUrl).toURL();
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException(directoryUrl, ex);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public JSON directory(ISession ISession, URI serverUri) throws AcmeException {
        // This is a workaround for a bug at SSL.com. It requires account registration
        // by EAB, but the "externalAccountRequired" flag in the directory is set to
        // false. This patch reads the directory and forcefully sets the flag to true.
        // The entire method can be removed once it is fixed on SSL.com side.
        var superdirectory = super.directory(ISession, serverUri);
        if (superdirectory == null) {
            return null;
        }

        var directory = superdirectory.toMap();
        var meta = directory.get("meta");
        if (meta instanceof Map) {
            var metaMap = ((Map<String, Object>) meta);
            metaMap.remove("externalAccountRequired");
            metaMap.put("externalAccountRequired", true);
        }
        return JSON.fromMap(directory);
    }

}
