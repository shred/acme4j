/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2018 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.connector;

import java.net.URL;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * This {@link Connection} is used for servers that do not implement the POST-as-GET
 * feature that was introduced in ACME draft-15.
 *
 * @since 2.4
 * @deprecated Only meant for compatibility purposes. If your server needs this
 *             connection, it should be fixed soon.
 */
@Deprecated
public class PreDraft15Connection extends DefaultConnection {

    private static final String MIME_JSON = "application/json";
    private static final String MIME_CERTIFICATE_CHAIN = "application/pem-certificate-chain";

    public PreDraft15Connection(HttpConnector httpConnector) {
        super(httpConnector);
    }

    @Override
    public int sendCertificateRequest(URL url, Login login) throws AcmeException {
        return sendRequest(url, login.getSession(), MIME_CERTIFICATE_CHAIN);
    }

    @Override
    public int sendSignedPostAsGetRequest(URL url, Login login) throws AcmeException {
        return sendRequest(url, login.getSession(), MIME_JSON);
    }

}
