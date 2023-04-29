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
package org.shredzone.acme4j.smime.challenge;

import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.provider.ChallengeProvider;
import org.shredzone.acme4j.provider.ChallengeType;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * A provider that generates {@link EmailReply00Challenge}. It is registered as Java
 * service.
 *
 * @since 2.12
 */
@ChallengeType(EmailReply00Challenge.TYPE)
public class EmailReply00ChallengeProvider implements ChallengeProvider {

    @Override
    public Challenge create(Login login, JSON data) {
        return new EmailReply00Challenge(login, data);
    }

}
