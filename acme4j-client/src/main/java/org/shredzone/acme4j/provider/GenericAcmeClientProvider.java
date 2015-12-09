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
package org.shredzone.acme4j.provider;

import java.net.URI;
import java.net.URISyntaxException;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.impl.GenericAcmeClient;

/**
 * A generic {@link AcmeClientProvider}. It should be working for all ACME servers
 * complying to the ACME specifications.
 * <p>
 * The {@code serverUri} is either a http or https URI to the server's directory service.
 *
 * @author Richard "Shred" Körber
 */
public class GenericAcmeClientProvider extends AbstractAcmeClientProvider {

    @Override
    public boolean accepts(String serverUri) {
        return serverUri.startsWith("http://") || serverUri.startsWith("https://");
    }

    @Override
    public AcmeClient connect(String serverUri) {
        if (!accepts(serverUri)) {
            throw new IllegalArgumentException("This provider does not accept " + serverUri);
        }

        try {
            URI directoryUri = new URI(serverUri);
            return new GenericAcmeClient(this, directoryUri);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException(serverUri, ex);
        }
    }

}
