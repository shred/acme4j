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
    public boolean accepts(URI serverUri) {
        return "http".equals(serverUri.getScheme())
                        || "https".equals(serverUri.getScheme());
    }

    @Override
    protected URI resolve(URI serverUri) {
        return serverUri;
    }

}
