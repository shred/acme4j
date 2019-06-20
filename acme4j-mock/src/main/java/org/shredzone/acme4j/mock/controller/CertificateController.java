/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.controller;

import java.net.URL;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.mock.connection.MockError;
import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockOrder;

/**
 * A {@link Controller} that handles certificate requests.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class CertificateController implements Controller {
    private final MockOrder order;

    /**
     * Creates a new {@link CertificateController}.
     *
     * @param order
     *         {@link MockOrder} that contains the certificate to be returned
     */
    public CertificateController(MockOrder order) {
        this.order = order;
    }

    /**
     * Returns the certificate chain, if set.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doPostAsGetRequest(URL requestUrl, PublicKey publicKey) throws AcmeException {
        List<X509Certificate> certChain = order.getCertificate();
        if (certChain == null) {
            throw MockError.notFound();
        }

        return new Result(certChain);
    }

}
