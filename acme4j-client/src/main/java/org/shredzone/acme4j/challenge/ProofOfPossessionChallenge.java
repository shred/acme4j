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
package org.shredzone.acme4j.challenge;

import java.security.PublicKey;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.util.ClaimBuilder;

/**
 * Implements the {@code proofOfPossession-01} challenge.
 * <p>
 * <em>TODO: Currently this challenge is not implemented.</em>
 *
 * @author Richard "Shred" Körber
 */
public class ProofOfPossessionChallenge extends GenericChallenge {
    private static final long serialVersionUID = 6212440828380185335L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "proofOfPossession-01";

    private PublicKey accountKey;

    @Override
    public void authorize(Account account) {
        super.authorize(account);
        accountKey = account.getKeyPair().getPublic();
    }

    @Override
    public void marshall(ClaimBuilder cb) {
        super.marshall(cb);
        cb.putKey("accountKey", accountKey);
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
