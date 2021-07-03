/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2021 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.smime.csr;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * An enumeration of key usage types for S/MIME certificates.
 *
 * @since 2.12
 */
public enum KeyUsageType {

    /**
     * S/MIME certificate can be used only for signing.
     */
    SIGNING_ONLY(KeyUsage.digitalSignature),

    /**
     * S/MIME certificate can be used only for encryption.
     */
    ENCRYPTION_ONLY(KeyUsage.keyEncipherment),

    /**
     * S/MIME certificate can be used for both signing and encryption.
     */
    SIGNING_AND_ENCRYPTION(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);

    private final int keyUsage;

    KeyUsageType(int keyUsage) {
        this.keyUsage = keyUsage;
    }

    /**
     * Returns the key usage bits to be used in the key usage extension of a CSR.
     */
    public int getKeyUsageBits() {
        return keyUsage;
    }

}
