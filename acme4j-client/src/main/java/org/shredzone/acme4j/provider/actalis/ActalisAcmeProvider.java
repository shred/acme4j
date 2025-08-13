/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2025 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.provider.actalis;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Map;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * An {@link AcmeProvider} for <em>Actalis</em>.
 * <p>
 * The {@code serverUri} is {@code "acme://actalis.com"} for the production server.
 * <p>
 * If you want to use <em>Actalis</em>, always prefer to use this provider.
 *
 * @see <a href="https://www.actalis.com/">Actalis S.p.A.</a>
 * @since 4.0.0
 */
public class ActalisAcmeProvider extends AbstractAcmeProvider {

    private static final String PRODUCTION_DIRECTORY_URL = "https://acme-api.actalis.com/acme/directory";

    @Override
    public boolean accepts(URI serverUri) {
        return "acme".equals(serverUri.getScheme())
                && "actalis.com".equals(serverUri.getHost());
    }

    @Override
    public URL resolve(URI serverUri) {
        var path = serverUri.getPath();
        String directoryUrl;
        if (path == null || path.isEmpty() || "/".equals(path)) {
            directoryUrl = PRODUCTION_DIRECTORY_URL;
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
    public JSON directory(Session session, URI serverUri) throws AcmeException {
        // This is a workaround as actalis.com uses "home" instead of "website" to
        // refer to its homepage in the metadata.
        var superdirectory = super.directory(session, serverUri);
        if (superdirectory == null) {
            return null;
        }

        var directory = superdirectory.toMap();
        var meta = directory.get("meta");
        if (meta instanceof Map) {
            var metaMap = ((Map<String, Object>) meta);
            if (metaMap.containsKey("home") && !metaMap.containsKey("website")) {
                metaMap.put("website", metaMap.remove("home"));
            }
        }
        return JSON.fromMap(directory);
    }


}
