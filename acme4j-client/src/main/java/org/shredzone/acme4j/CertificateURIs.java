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
package org.shredzone.acme4j;

import java.net.URI;

/**
 * Represents the URIs returned by a certificate request
 *
 * @author cargy
 */
public class CertificateURIs {

    private final URI certUri;
    private final URI chainCertUri;

    public CertificateURIs(URI certUri, URI chainCertUri) {
        this.certUri = certUri;
        this.chainCertUri = chainCertUri;
    }

    /**
     * The URI from which the client may fetch the certificate
     *
     * @return {@link URI} the certificate can be downloaded from
     */
    public URI getCertUri() {
        return certUri;
    }

    /**
     * The URI from which the client may fetch a chain of CA certificates
     *
     * @return {@link URI} the certificate chain can be downloaded from
     */
    public URI getChainCertUri() {
        return chainCertUri;
    }

}
