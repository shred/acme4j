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

/**
 * This package contains the
 * {@link org.shredzone.acme4j.smime.challenge.EmailReply00Challenge#TYPE} related acme4j
 * {@link org.shredzone.acme4j.challenge.Challenge} implementation.
 * <p>
 * The {@link org.shredzone.acme4j.smime.challenge.EmailReply00ChallengeProvider} is
 * registered as Java service, so acme4j is able to automatically generate
 * {@link org.shredzone.acme4j.smime.challenge.EmailReply00Challenge} instances.
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotationForFields(NonNull.class)
package org.shredzone.acme4j.smime.challenge;

import edu.umd.cs.findbugs.annotations.DefaultAnnotationForFields;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
